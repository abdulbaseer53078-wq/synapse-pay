package com.synapsepay.android

import android.app.Activity
import android.content.Intent
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException

/** Standard error codes, the same as the web SDK's. */
enum class SynapsePayErrorCode {
    ERR_NETWORK, ERR_CARD_INCOMPLETE, ERR_CARD_DECLINED, ERR_AUTHENTICATION_FAILED, ERR_CANCELED, ERR_TIMEOUT,
    ERR_INVALID_REQUEST, ERR_SYSTEM_ERROR
}

data class SynapsePayError(
    val code: SynapsePayErrorCode,
    val message: String,
    val retryable: Boolean,
    val apiCode: String? = null,
)

/** What the app may see of a payment intent. */
data class PaymentIntent(
    val id: String,
    val status: String,
    val amount: Long,
    val currency: String,
    val cardLast4: String?,
    val transactionId: String?,
    internal val nextActionUrl: String?,
    internal val lastError: JSONObject?,
) {
    companion object {
        fun from(json: JSONObject) = PaymentIntent(
            id = json.getString("id"),
            status = json.getString("status"),
            amount = json.getLong("amount"),
            currency = json.getString("currency"),
            cardLast4 = json.optJSONObject("card")?.optString("last4"),
            transactionId = json.optString("transaction_id").ifEmpty { null },
            nextActionUrl = json.optJSONObject("next_action")?.optString("url"),
            lastError = json.optJSONObject("last_payment_error"),
        )
    }
}

/** Either [paymentIntent] (check its status) or [error]. PROCESSING: the bank's answer is late; wait for your
 * server's webhook rather than charging again. */
data class PaymentResult(val paymentIntent: PaymentIntent? = null, val error: SynapsePayError? = null)

internal fun errorFromApi(json: JSONObject?): SynapsePayError {
    val apiCode = json?.optString("error_code")?.ifEmpty { null }
    val category = json?.optString("error_category")
    val code = when {
        apiCode == "AUTHENTICATION_FAILED" -> SynapsePayErrorCode.ERR_AUTHENTICATION_FAILED
        category == "SOFT_DECLINE" || category == "HARD_DECLINE" -> SynapsePayErrorCode.ERR_CARD_DECLINED
        category == "VALIDATION_ERROR" || category == "AUTHENTICATION_ERROR" -> SynapsePayErrorCode.ERR_INVALID_REQUEST
        else -> SynapsePayErrorCode.ERR_SYSTEM_ERROR
    }
    return SynapsePayError(code, json?.optString("error_message")?.ifEmpty { null } ?: "Something went wrong.",
                           json?.optBoolean("retryable") ?: false, apiCode)
}

private val NETWORK = SynapsePayError(SynapsePayErrorCode.ERR_NETWORK,
                                      "Couldn't reach Synapse Pay. Check your connection.", true)

/**
 * Synapse Pay for Android apps. Your server creates the payment intent with its secret key and sends the
 * client_secret to the app; the app collects the card in [CardInputView] and calls [confirmCardPayment].
 *
 * The card number is encrypted on the device to Synapse's checkout key ([CheckoutCrypto]) and only ciphertext
 * leaves the app. Your servers never see it.
 */
class SynapsePay(apiBase: String) {
    private val api = SynapsePayApi(apiBase)
    @Volatile private var crypto: CheckoutCrypto? = null

    private suspend fun checkoutCrypto(): CheckoutCrypto = crypto ?: withContext(Dispatchers.IO) {
        val response = api.checkoutKey()
        if (!response.ok()) throw IOException("checkout key unavailable")
        val jwk = JSONObject(response.body)
        CheckoutCrypto(jwk.getString("x"), jwk.getString("y")).also { crypto = it }
    }

    /**
     * Pays the intent with the card in [card], including the bank's 3-D Secure page (shown over [activity]) when
     * the bank asks for it. Safe to call again after an error: an intent is never charged twice.
     */
    suspend fun confirmCardPayment(activity: Activity, clientSecret: String, card: CardInputView): PaymentResult {
        val details = card.takeCard()
            ?: return PaymentResult(error = SynapsePayError(SynapsePayErrorCode.ERR_CARD_INCOMPLETE,
                                                            card.problem() ?: "Enter your card details.", false))
        val response = try {
            val crypto = checkoutCrypto()
            withContext(Dispatchers.Default) {
                Triple(crypto.seal(details.pan, "data"), crypto.seal(details.cvc, "cvv"), details)
            }.let { (encryptedCard, encryptedCvv, d) ->
                withContext(Dispatchers.IO) {
                    api.confirm(clientSecret, encryptedCard, encryptedCvv, d.expiryMmYy, d.brand)
                }
            }
        } catch (e: IOException) {
            return PaymentResult(error = NETWORK)
        } finally {
            details.wipe()
        }
        val json = JSONObject(response.body.ifEmpty { "{}" })
        if (!response.ok()) return PaymentResult(error = errorFromApi(json))
        var intent = PaymentIntent.from(json)
        if (intent.status == "REQUIRES_ACTION" && intent.nextActionUrl != null) {
            val completed = ThreeDsActivity.run(activity, api.apiBase() + intent.nextActionUrl)
            intent = retrieve(clientSecret).paymentIntent ?: return PaymentResult(error = NETWORK)
            if (!completed && intent.status == "REQUIRES_ACTION") {
                return PaymentResult(intent, SynapsePayError(SynapsePayErrorCode.ERR_CANCELED,
                                                             "Bank verification was closed before finishing.", true))
            }
        }
        return result(intent)
    }

    /** The intent's current state, as the app may see it. */
    suspend fun retrieve(clientSecret: String): PaymentResult = try {
        val response = withContext(Dispatchers.IO) { api.retrieve(clientSecret) }
        val json = JSONObject(response.body.ifEmpty { "{}" })
        if (response.ok()) result(PaymentIntent.from(json)) else PaymentResult(error = errorFromApi(json))
    } catch (e: IOException) {
        PaymentResult(error = NETWORK)
    }

    private fun result(intent: PaymentIntent): PaymentResult = when {
        intent.status == "CANCELED" ->
            PaymentResult(intent, SynapsePayError(SynapsePayErrorCode.ERR_CANCELED, "This payment was canceled.", false))
        intent.status == "REQUIRES_PAYMENT_METHOD" && intent.lastError != null ->
            PaymentResult(intent, errorFromApi(intent.lastError))
        else -> PaymentResult(intent)
    }
}

/** Card details taken from the view for one attempt; [wipe] clears them. */
internal class CardDetails(var pan: String, val expiryMmYy: String, var cvc: String, val brand: String) {
    fun wipe() { pan = ""; cvc = "" }
}

/** Launches [ThreeDsActivity] and waits for it without needing the caller's activity-result plumbing. */
internal object PendingChallenges {
    val waiting = mutableMapOf<String, CompletableDeferred<Boolean>>()

    fun start(activity: Activity, url: String, id: String): CompletableDeferred<Boolean> {
        val deferred = CompletableDeferred<Boolean>()
        synchronized(waiting) { waiting[id] = deferred }
        activity.startActivity(Intent(activity, ThreeDsActivity::class.java)
            .putExtra(ThreeDsActivity.EXTRA_URL, url).putExtra(ThreeDsActivity.EXTRA_ID, id))
        return deferred
    }

    fun finish(id: String, completed: Boolean) {
        synchronized(waiting) { waiting.remove(id) }?.complete(completed)
    }
}

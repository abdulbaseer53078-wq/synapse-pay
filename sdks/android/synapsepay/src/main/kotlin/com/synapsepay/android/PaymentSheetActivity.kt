package com.synapsepay.android

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

/**
 * A ready-made payment screen: card fields, a Pay button, 3-D Secure, then finishes with the result. For apps
 * (and the Flutter plugin) that don't want to build their own.
 *
 * Start it with [intent]; read the result with [parseResult].
 */
class PaymentSheetActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val apiBase = intent.getStringExtra(EXTRA_API_BASE) ?: return finish()
        val clientSecret = intent.getStringExtra(EXTRA_CLIENT_SECRET) ?: return finish()
        val synapse = SynapsePay(apiBase)
        val card = CardInputView(this)
        val message = TextView(this)
        val pay = Button(this).apply { text = intent.getStringExtra(EXTRA_PAY_LABEL) ?: "Pay"; isEnabled = false }
        card.onChange = { complete, _ -> pay.isEnabled = complete }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
            addView(card); addView(message); addView(pay)
        })
        pay.setOnClickListener {
            pay.isEnabled = false
            lifecycleScope.launch {
                val result = synapse.confirmCardPayment(this@PaymentSheetActivity, clientSecret, card)
                val error = result.error
                if (error != null && error.retryable || error?.code == SynapsePayErrorCode.ERR_CARD_DECLINED
                    || error?.code == SynapsePayErrorCode.ERR_AUTHENTICATION_FAILED
                    || error?.code == SynapsePayErrorCode.ERR_CARD_INCOMPLETE) {
                    message.text = error.message // let the customer fix it or try another card
                    pay.isEnabled = true
                    return@launch
                }
                setResult(Activity.RESULT_OK, Intent()
                    .putExtra(RESULT_STATUS, result.paymentIntent?.status)
                    .putExtra(RESULT_ERROR_CODE, error?.code?.name)
                    .putExtra(RESULT_ERROR_MESSAGE, error?.message))
                finish()
            }
        }
    }

    companion object {
        const val EXTRA_API_BASE = "com.synapsepay.android.API_BASE"
        const val EXTRA_CLIENT_SECRET = "com.synapsepay.android.CLIENT_SECRET"
        const val EXTRA_PAY_LABEL = "com.synapsepay.android.PAY_LABEL"
        const val RESULT_STATUS = "status"
        const val RESULT_ERROR_CODE = "error_code"
        const val RESULT_ERROR_MESSAGE = "error_message"

        fun intent(activity: Activity, apiBase: String, clientSecret: String, payLabel: String = "Pay"): Intent =
            Intent(activity, PaymentSheetActivity::class.java)
                .putExtra(EXTRA_API_BASE, apiBase).putExtra(EXTRA_CLIENT_SECRET, clientSecret)
                .putExtra(EXTRA_PAY_LABEL, payLabel)

        /** (status, errorCode, errorMessage); a canceled sheet returns errorCode ERR_CANCELED. */
        fun parseResult(resultCode: Int, data: Intent?): Triple<String?, String?, String?> =
            if (resultCode != Activity.RESULT_OK || data == null) Triple(null, "ERR_CANCELED", "Payment canceled.")
            else Triple(data.getStringExtra(RESULT_STATUS), data.getStringExtra(RESULT_ERROR_CODE),
                        data.getStringExtra(RESULT_ERROR_MESSAGE))
    }
}

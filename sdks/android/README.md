# Synapse Pay for Android

Take card payments in Android apps. `minSdk 26`. Kotlin coroutines.

> **Status:** the security-critical core (`CheckoutCrypto`, `CardValidation`, `SynapsePayApi`, plain Java) is
> tested on a JVM against the real card service (`backend/tests/test_checkout_browser.py`). The Kotlin views and
> activities have **not been compiled yet**: build with Android Studio and fix anything it reports before use.

```kotlin
// build.gradle.kts
implementation("com.synapsepay:synapsepay-android:0.1.0")
```

```kotlin
val synapse = SynapsePay("https://YOUR-SYNAPSE-HOST")
// layout: <com.synapsepay.android.CardInputView android:id="@+id/card" ... />

payButton.setOnClickListener {
    lifecycleScope.launch {
        val clientSecret = myServer.createPayment()   // your server, with @synapsepay/node
        val result = synapse.confirmCardPayment(this@CheckoutActivity, clientSecret, binding.card)
        when {
            result.error != null -> show(result.error.message)        // codes match the web SDK
            result.paymentIntent?.status == "SUCCEEDED" -> showThanks()
            else -> show("We're confirming your payment.")           // PROCESSING: wait for your webhook
        }
    }
}
```

Or the ready-made screen: `startActivityForResult(PaymentSheetActivity.intent(this, apiBase, clientSecret), 1)`.

The card is encrypted on the device to Synapse's checkout key (the same `sp2` envelope as the web card frame).
The app process does hold the digits while the customer types, so a native card form puts the app in a larger
PCI DSS scope than the web iframe (SAQ A-EP rather than SAQ A). 3-D Secure opens the bank's page in a WebView.

Publish: `./gradlew :synapsepay:publishToMavenLocal`, or configure Maven Central credentials and signing.

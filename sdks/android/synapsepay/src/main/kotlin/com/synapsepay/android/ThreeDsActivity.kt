package com.synapsepay.android

import android.annotation.SuppressLint
import android.app.Activity
import android.net.Uri
import android.os.Bundle
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import java.util.UUID

/**
 * Shows the bank's 3-D Secure page. The page ends by loading synapsepay-sdk://3ds-complete, which this activity
 * intercepts; pressing back cancels.
 */
class ThreeDsActivity : AppCompatActivity() {
    private lateinit var id: String
    private var reported = false

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        id = intent.getStringExtra(EXTRA_ID) ?: return finish()
        val url = Uri.parse(intent.getStringExtra(EXTRA_URL) ?: return finish()).buildUpon()
            .appendQueryParameter("return_url", RETURN_URL).build()
        val web = WebView(this)
        web.settings.javaScriptEnabled = true // the bank's page needs it
        web.settings.allowFileAccess = false
        web.settings.allowContentAccess = false
        web.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val target = request.url
                if (target.toString().startsWith(RETURN_URL)) {
                    done(target.getQueryParameter("status") != "CANCELED_BY_CUSTOMER")
                    return true
                }
                return false
            }
        }
        setContentView(web)
        web.loadUrl(url.toString())
    }

    private fun done(completed: Boolean) {
        if (!reported) {
            reported = true
            PendingChallenges.finish(id, completed)
        }
        finish()
    }

    @Deprecated("Back cancels the verification")
    override fun onBackPressed() {
        done(false)
    }

    override fun onDestroy() {
        if (isFinishing) done(false)
        super.onDestroy()
    }

    companion object {
        const val EXTRA_URL = "com.synapsepay.android.URL"
        const val EXTRA_ID = "com.synapsepay.android.ID"
        private const val RETURN_URL = "synapsepay-sdk://3ds-complete"

        /** Shows the page over [activity]; true if the customer finished it, false if they backed out. */
        suspend fun run(activity: Activity, url: String): Boolean =
            PendingChallenges.start(activity, url, UUID.randomUUID().toString()).await()
    }
}

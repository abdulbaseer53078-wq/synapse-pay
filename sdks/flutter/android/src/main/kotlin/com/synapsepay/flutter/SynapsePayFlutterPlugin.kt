package com.synapsepay.flutter

import android.app.Activity
import android.content.Intent
import com.synapsepay.android.PaymentSheetActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.PluginRegistry

/** Bridges Dart's presentPaymentSheet to the native Synapse Pay payment sheet. */
class SynapsePayFlutterPlugin : FlutterPlugin, ActivityAware, MethodChannel.MethodCallHandler,
    PluginRegistry.ActivityResultListener {

    private lateinit var channel: MethodChannel
    private var activity: Activity? = null
    private var pending: MethodChannel.Result? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "com.synapsepay/flutter")
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        if (call.method != "presentPaymentSheet") return result.notImplemented()
        val activity = activity ?: return result.error("NO_ACTIVITY", "No foreground activity", null)
        if (pending != null) return result.error("BUSY", "A payment sheet is already open", null)
        val apiBase = call.argument<String>("apiBase") ?: return result.error("ARGS", "apiBase is required", null)
        val secret = call.argument<String>("clientSecret") ?: return result.error("ARGS", "clientSecret is required", null)
        pending = result
        activity.startActivityForResult(
            PaymentSheetActivity.intent(activity, apiBase, secret, call.argument<String>("payLabel") ?: "Pay"),
            REQUEST_CODE)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode != REQUEST_CODE) return false
        val (status, errorCode, errorMessage) = PaymentSheetActivity.parseResult(resultCode, data)
        pending?.success(mapOf("status" to status, "errorCode" to errorCode, "errorMessage" to errorMessage))
        pending = null
        return true
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addActivityResultListener(this)
    }

    override fun onDetachedFromActivityForConfigChanges() { activity = null }
    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) = onAttachedToActivity(binding)
    override fun onDetachedFromActivity() { activity = null }

    private companion object {
        const val REQUEST_CODE = 0x5e9a
    }
}

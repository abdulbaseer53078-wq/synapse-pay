/// Synapse Pay for Flutter. Card details are typed into the native Synapse Pay payment sheet (Android today), so
/// they never pass through Dart code or your servers.
library synapsepay_flutter;

import 'package:flutter/services.dart';

/// The same codes as the web and Android SDKs.
enum SynapsePayErrorCode {
  network,
  cardIncomplete,
  cardDeclined,
  authenticationFailed,
  canceled,
  timeout,
  invalidRequest,
  systemError,
}

class SynapsePayError {
  const SynapsePayError(this.code, this.message);
  final SynapsePayErrorCode code;
  final String message;

  static SynapsePayErrorCode _parse(String? code) => switch (code) {
        'ERR_NETWORK' => SynapsePayErrorCode.network,
        'ERR_CARD_INCOMPLETE' => SynapsePayErrorCode.cardIncomplete,
        'ERR_CARD_DECLINED' => SynapsePayErrorCode.cardDeclined,
        'ERR_AUTHENTICATION_FAILED' => SynapsePayErrorCode.authenticationFailed,
        'ERR_CANCELED' => SynapsePayErrorCode.canceled,
        'ERR_TIMEOUT' => SynapsePayErrorCode.timeout,
        'ERR_INVALID_REQUEST' => SynapsePayErrorCode.invalidRequest,
        _ => SynapsePayErrorCode.systemError,
      };

  @override
  String toString() => 'SynapsePayError($code, $message)';
}

/// [status] is the payment intent's status: SUCCEEDED means paid; PROCESSING means the bank's answer is late (wait
/// for your server's webhook, don't charge again).
class PaymentResult {
  const PaymentResult({this.status, this.error});
  final String? status;
  final SynapsePayError? error;

  bool get succeeded => status == 'SUCCEEDED' && error == null;
}

class SynapsePay {
  SynapsePay({required this.apiBase});

  /// Synapse Pay's API origin, e.g. "https://sandbox.synapsepay.example".
  final String apiBase;

  static const MethodChannel _channel = MethodChannel('com.synapsepay/flutter');

  /// Shows the payment sheet for the intent your server created (its client_secret), including the bank's
  /// 3-D Secure page. Resolves when the customer pays, or closes the sheet.
  Future<PaymentResult> presentPaymentSheet(String clientSecret, {String payLabel = 'Pay'}) async {
    final result = await _channel.invokeMapMethod<String, Object?>('presentPaymentSheet', {
      'apiBase': apiBase,
      'clientSecret': clientSecret,
      'payLabel': payLabel,
    });
    final code = result?['errorCode'] as String?;
    return PaymentResult(
      status: result?['status'] as String?,
      error: code == null ? null : SynapsePayError(SynapsePayError._parse(code), (result?['errorMessage'] as String?) ?? ''),
    );
  }
}

# synapsepay_flutter

Card payments in Flutter apps through the native Synapse Pay payment sheet.

> **Status:** Android only, and **not compiled yet** (this was written where no Flutter or Android SDK was
> available). Build it in a Flutter project and fix anything the analyzer reports. iOS needs the native iOS SDK,
> which doesn't exist yet. React Native isn't started.

```dart
final synapse = SynapsePay(apiBase: 'https://YOUR-SYNAPSE-HOST');

final clientSecret = await myServer.createPayment();   // your server, with @synapsepay/node
final result = await synapse.presentPaymentSheet(clientSecret, payLabel: 'Pay ₹500');
if (result.succeeded) {
  showThanks();
} else if (result.error != null) {
  showMessage(result.error!.message);
} // status PROCESSING: wait for your server's webhook
```

The card is typed into the native sheet and encrypted there, so it never passes through Dart.

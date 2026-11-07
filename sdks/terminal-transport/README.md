# terminal-transport

Multi-path connectivity for SynapsePay payment terminals (Stage 4, Step 16). Plain Java 8, no dependencies, so it
runs unchanged on Android POS devices. Not for the shopper-facing SDKs: browsers can't choose a network interface,
and a shopper's phone already moves between Wi-Fi and cellular on its own.

| Class | Job |
| --- | --- |
| `NetworkPath` | One interface (Ethernet, Wi-Fi, cellular). Opens connections bound to it. |
| `PathSelector` | Picks the path: highest priority that is up and not weak. Tells listeners when it changes. |
| `HealthProber` | `HEAD /health` over each path, so "connected to Wi-Fi" also means "reaches the cloud". |
| `TransactionSender` | Sends one transaction, moving to another path on failure, until the cloud gives a final answer. |

## Behaviour

- **Priority.** Paths in priority order, cheapest first. Traffic returns to Wi-Fi as soon as it is healthy again.
- **Down.** At once when the OS reports the link lost or a send fails at the network level. Otherwise after 3 failed
  probes in a row. Back up only after 3 good probes in a row, so a flapping router can't bounce traffic.
- **Weak Wi-Fi.** Below −80 dBm the path is avoided before the next transaction; it's trusted again above −70 dBm.
  The gap prevents flapping.
- **Timeouts.** 800 ms connect, 2 s read. A timeout resends the same bytes on another path.
- **Same payload, always.** The serialized request is copied once and every attempt sends exactly those bytes. The
  cloud then either processes it once, replays its answer, or answers `409` "still processing" (retryable), which
  the sender polls every 250 ms. **Never rebuild or re-encrypt the request between attempts:** a different body
  with the same `idempotency_key` is rejected as a conflict.
- **Mid-request link loss.** When the active path goes down, the in-flight attempt is aborted at once instead of
  waiting out its read timeout. That is what makes failover after a cable pull sub-second.
- **Deadline.** 30 s, longer than the cloud's 15 s acquirer timeout. Past it, `OutcomeUnknownException`: resend the
  same payload later to learn the outcome. Never treat it as a decline.

## What the chaos test proves

`./run-tests.sh` (JDK 17+; prints one line per scenario, exits non-zero on failure). Wi-Fi and cellular are local TCP
proxies in front of a fake cloud with the real idempotency rules and an acquirer that takes 1.5 s.

| Failure | Result |
| --- | --- |
| Cable pulled mid-request (OS reports the link lost) | Same payload on cellular ~3 ms after the cut; answer ≤ acquirer time + 250 ms; one charge |
| Wi-Fi silently dead mid-request (no OS signal) | Noticed by the 2 s read timeout, then cellular; one charge |
| Wi-Fi dead before sending (cloud never saw it) | Processed fresh over cellular; one charge |
| Probe failures / recoveries | Demoted after 3, restored after 3; the UI listener told each time |
| Every path down | `NoPathException` at once; nothing sent |

The gate this enforces: after a hard link loss the payload is resent on the next path within 1 s, and the final
answer arrives no later than the acquirer's own response time plus 1 s, with exactly one charge. A result can't come
back faster than the acquirer answers the original. A silent failure is bounded by the read timeout instead.

On a real device, add cellular latency: a fresh mutual-TLS handshake over LTE is typically 300–600 ms. To stay well
under 1 s, keep the cellular path warm (the prober's standby probes keep its connection pooled), at the cost of a
little metered data.

## Android wiring (untested here: no Android SDK in this environment)

```java
// A NetworkPath for one android.net.Network: connections are bound to that interface.
final class AndroidPath implements NetworkPath {
    final Network network; final Kind kind;
    AndroidPath(Network network, Kind kind) { this.network = network; this.kind = kind; }
    public String name() { return kind.name().toLowerCase(); }
    public Kind kind() { return kind; }
    public URLConnection open(URL url) throws IOException { return network.openConnection(url); }
}

// Keep cellular up alongside Wi-Fi (needs CHANGE_NETWORK_STATE), and report link loss at once.
ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
NetworkRequest cellular = new NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR).build();
cm.requestNetwork(cellular, new ConnectivityManager.NetworkCallback() {
    @Override public void onLost(Network n) { selector.linkLost(pathFor(n)); }
});
// Same for TRANSPORT_WIFI / TRANSPORT_ETHERNET; feed WifiInfo.getRssi() to selector.signal(wifiPath, rssi).
// Show the 4G icon from selector.addListener((previous, active) -> ...).
```

`PathSelector` takes its paths at construction, so build it once both networks are available. Wiring paths that
appear later (a cable plugged in after boot) is the terminal app's job until this library supports it.

## Not built

- **Tertiary offline queue.** With every path down, sends fail fast (`NoPathException`); hand them to the offline queue
  once it exists.
- **Mesh paths.**
- **A real-device test.** Interface binding (`Network.openConnection`) only exists on Android.

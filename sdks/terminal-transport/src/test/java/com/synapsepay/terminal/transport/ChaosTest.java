package com.synapsepay.terminal.transport;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Step 16.5 chaos test: Wi-Fi and cellular are two local TCP proxies in front of a fake cloud that implements the
 * real idempotency rules and counts acquirer charges. Each scenario breaks the Wi-Fi proxy mid-transaction.
 *
 * <p>Gate (agreed): after a hard link loss the same payload is resent on cellular within 1 s; the final answer
 * arrives no later than the acquirer's own response time + 1 s; exactly one charge. A silent failure (router up,
 * internet gone) can only be noticed by the read timeout, so its bound is 2 s + 1 s.
 *
 * <p>Run: see README ({@code ./run-tests.sh}). Exits non-zero if any scenario fails.
 */
public final class ChaosTest {
    static final long ACQUIRER_MS = 1_500; // the acquirer's answer time for every transaction
    static final URL TRANSACTIONS = url("http://cloud.synapsepay.test/api/v1/transactions");
    static final URL HEALTH = url("http://cloud.synapsepay.test/health");
    static final ExecutorService POOL = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r);
        t.setDaemon(true);
        return t;
    });

    public static void main(String[] args) {
        Map<String, Scenario> scenarios = new LinkedHashMap<>();
        scenarios.put("cable pulled mid-flight: resent on cellular < 1 s, one charge", ChaosTest::cablePulled);
        scenarios.put("Wi-Fi silently dead mid-flight: read timeout, then cellular, one charge", ChaosTest::silentLoss);
        scenarios.put("request never reached the cloud: processed fresh on cellular, one charge", ChaosTest::neverArrived);
        scenarios.put("probes: 3 failures demote, 3 successes restore, UI told each time", ChaosTest::probeHysteresis);
        scenarios.put("running prober demotes a dead Wi-Fi on its own", ChaosTest::backgroundProber);
        scenarios.put("signal: below -80 dBm leaves Wi-Fi, back only above -70 dBm", ChaosTest::signalHysteresis);
        scenarios.put("every path down: fails fast, nothing sent", ChaosTest::noPath);
        int failed = 0;
        for (Map.Entry<String, Scenario> s : scenarios.entrySet()) {
            long start = System.nanoTime();
            try {
                s.getValue().run();
                System.out.printf("PASS %-78s %5d ms%n", s.getKey(), ms(System.nanoTime() - start));
            } catch (Throwable e) {
                failed++;
                System.out.printf("FAIL %s%n     %s%n", s.getKey(), e);
            }
        }
        System.out.printf("%d passed, %d failed%n", scenarios.size() - failed, failed);
        System.exit(failed == 0 ? 0 : 1);
    }

    // --- scenarios -------------------------------------------------------------------------------------------------

    /** Ethernet/Wi-Fi cable pulled while the cloud is waiting on the acquirer; the OS reports the link lost. */
    static void cablePulled() throws Exception {
        try (FakeCloud cloud = new FakeCloud(); Proxy wifi = new Proxy(cloud.port()); Proxy cell = new Proxy(cloud.port())) {
            Net net = new Net(wifi, cell);
            Future<TransactionSender.Response> pending = POOL.submit(() -> net.sender.send(payload()));
            Thread.sleep(300);
            check(cloud.charges.get() == 1, "the request reached the cloud before the cut");
            long cut = System.nanoTime();
            wifi.cut();
            net.selector.linkLost(net.wifi); // Android: ConnectivityManager.NetworkCallback.onLost
            TransactionSender.Response r = pending.get(10, TimeUnit.SECONDS);

            check(r.status == 201 && r.path == net.cell, "completed over cellular: " + r.status + " via " + r.path.name());
            check(cloud.charges.get() == 1, "exactly one charge, got " + cloud.charges.get());
            long resent = ms(cell.firstConnect - cut);
            check(resent < 1_000, "resent on cellular within 1 s of the cut: " + resent + " ms");
            long total = ms(System.nanoTime() - cut) + 300;
            check(total <= ACQUIRER_MS + 1_000, "answer within acquirer time + 1 s: " + total + " ms");
            check(net.ui.equals(List.of("cellular")), "cashier shown the switch once: " + net.ui);
            System.out.printf("     cut -> resent on cellular: %d ms; cut -> final answer: %d ms (acquirer %d ms)%n",
                              resent, total - 300, ACQUIRER_MS - 300);
        }
    }

    /** The router stays up but its internet is gone: no OS signal, bytes just stop. */
    static void silentLoss() throws Exception {
        try (FakeCloud cloud = new FakeCloud(); Proxy wifi = new Proxy(cloud.port()); Proxy cell = new Proxy(cloud.port())) {
            Net net = new Net(wifi, cell);
            long start = System.nanoTime();
            Future<TransactionSender.Response> pending = POOL.submit(() -> net.sender.send(payload()));
            Thread.sleep(300);
            wifi.blackhole();
            TransactionSender.Response r = pending.get(10, TimeUnit.SECONDS);

            check(r.status == 201 && r.path == net.cell, "completed over cellular");
            check(cloud.charges.get() == 1, "exactly one charge, got " + cloud.charges.get());
            long total = ms(System.nanoTime() - start);
            check(total <= net.sender.readTimeoutMs + 1_000, "silent loss bounded by read timeout + 1 s: " + total + " ms");
        }
    }

    /** Wi-Fi was already silently dead, so the cloud never saw the first copy. */
    static void neverArrived() throws Exception {
        try (FakeCloud cloud = new FakeCloud(); Proxy wifi = new Proxy(cloud.port()); Proxy cell = new Proxy(cloud.port())) {
            Net net = new Net(wifi, cell);
            wifi.blackhole();
            TransactionSender.Response r = net.sender.send(payload());
            check(r.status == 201 && r.path == net.cell, "completed over cellular");
            check(cloud.charges.get() == 1, "processed once, fresh, got " + cloud.charges.get());
        }
    }

    static void probeHysteresis() throws Exception {
        try (FakeCloud cloud = new FakeCloud(); Proxy wifi = new Proxy(cloud.port()); Proxy cell = new Proxy(cloud.port())) {
            Net net = new Net(wifi, cell);
            HealthProber prober = new HealthProber(net.selector, HEALTH, 800);
            check(prober.probe(net.wifi), "a live path passes its probe");
            net.selector.probeResult(net.wifi, false);
            net.selector.probeResult(net.wifi, false);
            check(net.selector.active() == net.wifi, "two failures aren't enough");
            net.selector.probeResult(net.wifi, false);
            check(net.selector.active() == net.cell, "third failure demotes Wi-Fi");
            net.selector.probeResult(net.wifi, true);
            net.selector.probeResult(net.wifi, true);
            check(net.selector.active() == net.cell, "two successes aren't enough to come back");
            net.selector.probeResult(net.wifi, true);
            check(net.selector.active() == net.wifi, "third success restores Wi-Fi (data saver)");
            check(net.ui.equals(List.of("cellular", "wifi")), "UI told of both switches: " + net.ui);
            wifi.cut();
            long start = System.nanoTime();
            check(!prober.probe(net.wifi), "a dead path fails its probe");
            check(ms(System.nanoTime() - start) < 1_000, "probe fails within its timeout");
        }
    }

    static void backgroundProber() throws Exception {
        try (FakeCloud cloud = new FakeCloud(); Proxy wifi = new Proxy(cloud.port()); Proxy cell = new Proxy(cloud.port())) {
            Net net = new Net(wifi, cell);
            try (HealthProber prober = new HealthProber(net.selector, HEALTH, 300)) {
                prober.start(100, 5);
                wifi.cut(); // no OS signal: only the probes can notice
                long deadline = System.nanoTime() + 3_000_000_000L;
                while (net.selector.active() != net.cell && System.nanoTime() < deadline) Thread.sleep(20);
                check(net.selector.active() == net.cell, "prober moved traffic to cellular");
            }
        }
    }

    static void signalHysteresis() {
        Net net = new Net(null, null);
        net.selector.signal(net.wifi, -81);
        check(net.selector.active() == net.cell, "weak Wi-Fi avoided before the next transaction");
        net.selector.signal(net.wifi, -75);
        check(net.selector.active() == net.cell, "-75 dBm isn't recovered yet (no flapping)");
        net.selector.signal(net.wifi, -65);
        check(net.selector.active() == net.wifi, "recovered above -70 dBm");
        net.selector.signal(net.wifi, -85);
        net.selector.linkLost(net.cell);
        check(net.selector.active() == net.wifi, "weak Wi-Fi beats no path");
    }

    static void noPath() throws Exception {
        try (FakeCloud cloud = new FakeCloud(); Proxy wifi = new Proxy(cloud.port()); Proxy cell = new Proxy(cloud.port())) {
            Net net = new Net(wifi, cell);
            net.selector.linkLost(net.wifi);
            net.selector.linkLost(net.cell);
            try {
                net.sender.send(payload());
                check(false, "send should fail");
            } catch (TransactionSender.NoPathException expected) {
                check(cloud.charges.get() == 0 && net.ui.get(net.ui.size() - 1).equals("none"), "nothing sent; UI shows offline");
            }
        }
    }

    // --- fixtures --------------------------------------------------------------------------------------------------

    interface Scenario {
        void run() throws Exception;
    }

    static void check(boolean ok, String what) {
        if (!ok) throw new AssertionError(what);
    }

    static long ms(long nanos) {
        return TimeUnit.NANOSECONDS.toMillis(nanos);
    }

    static URL url(String s) {
        try {
            return URI.create(s).toURL();
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static byte[] payload() {
        return ("{\"idempotency_key\":\"" + UUID.randomUUID() + "\",\"amount\":15000,\"currency\":\"INR\","
                + "\"payment_method\":\"CARD\",\"terminal_id\":\"TERM0001\"}").getBytes(UTF_8);
    }

    /** Two paths (Wi-Fi first), a selector, a sender, and what the cashier's screen was told. */
    static final class Net {
        final NetworkPath wifi;
        final NetworkPath cell;
        final PathSelector selector;
        final TransactionSender sender;
        final List<String> ui = new CopyOnWriteArrayList<>();

        Net(Proxy wifiProxy, Proxy cellProxy) {
            wifi = new ProxyPath("wifi", NetworkPath.Kind.WIFI, wifiProxy);
            cell = new ProxyPath("cellular", NetworkPath.Kind.CELLULAR, cellProxy);
            selector = new PathSelector(List.of(wifi, cell));
            selector.addListener((previous, active) -> ui.add(active == null ? "none" : active.name()));
            sender = new TransactionSender(selector, TRANSACTIONS, null);
        }
    }

    /** A path whose traffic goes through one local proxy (on a terminal: one network interface). */
    record ProxyPath(String name, Kind kind, Proxy proxy) implements NetworkPath {
        @Override
        public URLConnection open(URL url) throws IOException {
            return URI.create("http://127.0.0.1:" + proxy.port() + url.getFile()).toURL().openConnection();
        }
    }

    /** The cloud's idempotency rules (spec + backend StillProcessing), with an acquirer that takes ACQUIRER_MS. */
    static final class FakeCloud implements AutoCloseable {
        static final Pattern KEY = Pattern.compile("\"idempotency_key\":\"([^\"]+)\"");
        final AtomicInteger charges = new AtomicInteger();
        private final Map<String, Entry> entries = new HashMap<>();
        private final HttpServer server;

        static final class Entry {
            final byte[] body;
            volatile String response;

            Entry(byte[] body) {
                this.body = body;
            }
        }

        FakeCloud() throws IOException {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            server.setExecutor(POOL);
            server.createContext("/health", ex -> {
                ex.sendResponseHeaders(200, -1);
                ex.close();
            });
            server.createContext("/api/v1/transactions", this::transaction);
            server.start();
        }

        int port() {
            return server.getAddress().getPort();
        }

        private void transaction(HttpExchange ex) throws IOException {
            byte[] body = ex.getRequestBody().readAllBytes();
            Matcher m = KEY.matcher(new String(body, UTF_8));
            if (!m.find()) {
                reply(ex, 400, "{\"error_code\":\"INVALID_REQUEST\",\"retryable\":false}");
                return;
            }
            Entry e;
            boolean ours = false;
            synchronized (entries) {
                e = entries.get(m.group(1));
                if (e == null) {
                    entries.put(m.group(1), e = new Entry(body));
                    ours = true;
                }
            }
            if (ours) {
                charges.incrementAndGet(); // sent to the acquirer
                try {
                    Thread.sleep(ACQUIRER_MS);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
                e.response = "{\"status\":\"CAPTURED\"}";
                reply(ex, 201, e.response); // may fail: the client's connection could be gone
            } else if (!Arrays.equals(e.body, body)) {
                reply(ex, 409, "{\"error_code\":\"IDEMPOTENCY_KEY_CONFLICT\",\"retryable\":false}");
            } else if (e.response == null) {
                reply(ex, 409, "{\"error_code\":\"IDEMPOTENCY_KEY_CONFLICT\",\"error_category\":\"SYSTEM_ERROR\",\"retryable\":true}");
            } else {
                reply(ex, 201, e.response); // replay
            }
        }

        private static void reply(HttpExchange ex, int status, String json) {
            byte[] bytes = json.getBytes(UTF_8);
            try (OutputStream out = ex.getResponseBody()) {
                ex.sendResponseHeaders(status, bytes.length);
                out.write(bytes);
            } catch (IOException ignored) {
                // the client hung up
            } finally {
                ex.close();
            }
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    /** A TCP relay standing in for one network interface. cut(): link lost. blackhole(): bytes vanish silently. */
    static final class Proxy implements AutoCloseable {
        private final ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
        private volatile boolean blackhole;
        volatile long firstConnect;

        Proxy(int target) throws IOException {
            POOL.submit(() -> {
                while (!server.isClosed()) {
                    try {
                        Socket client = server.accept();
                        if (firstConnect == 0) firstConnect = System.nanoTime();
                        Socket upstream = new Socket(InetAddress.getLoopbackAddress(), target);
                        sockets.add(client);
                        sockets.add(upstream);
                        POOL.submit(() -> pump(client, upstream));
                        POOL.submit(() -> pump(upstream, client));
                    } catch (IOException e) {
                        return null;
                    }
                }
                return null;
            });
        }

        int port() {
            return server.getLocalPort();
        }

        private void pump(Socket from, Socket to) {
            byte[] buf = new byte[8192];
            try (InputStream in = from.getInputStream(); OutputStream out = to.getOutputStream()) {
                for (int n; (n = in.read(buf)) != -1; ) {
                    if (!blackhole) {
                        out.write(buf, 0, n);
                        out.flush();
                    }
                }
            } catch (IOException ignored) {
                // either side closed
            } finally {
                closeQuietly(from);
                closeQuietly(to);
            }
        }

        void blackhole() {
            blackhole = true;
        }

        void cut() {
            closeQuietly(server);
            for (Socket s : new ArrayList<>(sockets)) closeQuietly(s);
        }

        private static void closeQuietly(AutoCloseable c) {
            try {
                c.close();
            } catch (Exception ignored) {
                // already closed
            }
        }

        @Override
        public void close() {
            cut();
        }
    }
}

package com.synapsepay.terminal.transport;

import static com.synapsepay.terminal.transport.ChaosTest.check;
import static com.synapsepay.terminal.transport.ChaosTest.ms;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * Step 25 gate: Terminal A has no link of its own, yet its payment reaches the cloud through Terminal B in under
 * 2 s, and the cloud sees A's certificate, not B's. Terminals only relay for, and only through, terminals of the
 * same merchant, a relay goes nowhere but the cloud, and with no neighbour A gives up within 500 ms.
 *
 * <p>Real certificates (keytool, from the JDK): a terminal CA issuing client-auth-only terminal certificates, as
 * the production CA does, a rogue CA, and an HTTPS cloud that requires a terminal client certificate.
 */
public final class MeshTest {
    interface Scenario {
        void run() throws Exception;
    }

    static final char[] PASS = "changeit".toCharArray();
    static final String A = UUID.randomUUID().toString(), B = UUID.randomUUID().toString();
    static final String OTHER_MERCHANT = UUID.randomUUID().toString();
    static final Set<String> MERCHANT = new HashSet<>(Arrays.asList(A, B));
    static final byte[] PAYLOAD = "{\"idempotency_key\":\"k1\",\"amount\":50000}".getBytes(UTF_8);

    static Pki pki;

    public static void main(String[] args) throws Exception {
        pki = new Pki(Files.createTempDirectory("mesh-pki"));
        Map<String, Scenario> scenarios = new LinkedHashMap<>();
        scenarios.put("A offline: discovers B, payment relayed to the cloud as A, under 2 s", MeshTest::relayed);
        scenarios.put("B refuses to relay for another merchant's terminal", MeshTest::otherMerchantRefused);
        scenarios.put("A refuses a relay whose certificate isn't from the terminal CA", MeshTest::rogueRelayRefused);
        scenarios.put("a relay only goes to the cloud: CONNECT elsewhere is 403", MeshTest::notAnOpenProxy);
        scenarios.put("no neighbour: NoPathException within 500 ms, ready for the offline queue", MeshTest::noNeighbour);
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

    static void relayed() throws Exception {
        try (Cloud cloud = new Cloud();
             MeshRelay relay = new MeshRelay(pki.mesh("b", MERCHANT::contains), 0, cloud.authority(),
                                             SocketFactory.getDefault());
             Lan lan = new Lan()) {
            MeshDiscovery bSide = lan.discovery(B);
            MeshDiscovery aSide = lan.discovery(A);
            bSide.announce(relay.port(), () -> true, 200);
            long waited = System.nanoTime();
            while (aSide.neighbour() == null && ms(System.nanoTime() - waited) < 3_000) Thread.sleep(20);
            check(aSide.neighbour() != null, "A heard B's announcement");

            try (MeshPath mesh = new MeshPath(pki.mesh("a", MERCHANT::contains), aSide)) {
                TransactionSender sender = sender(mesh, cloud);
                long start = System.nanoTime();
                TransactionSender.Response r = sender.send(PAYLOAD);
                long took = ms(System.nanoTime() - start);
                check(r.status == 201 && r.path == mesh, "approved over the mesh: " + r.status + " via " + r.path.name());
                check(cloud.callers.equals(Arrays.asList(A)), "the cloud saw A's own certificate: " + cloud.callers);
                check(took < 2_000, "relayed in under 2 s: " + took + " ms");
            }
        }
    }

    static void otherMerchantRefused() throws Exception {
        try (Cloud cloud = new Cloud();
             MeshRelay relay = new MeshRelay(pki.mesh("b", MERCHANT::contains), 0, cloud.authority(),
                                             SocketFactory.getDefault());
             // C trusts B (it would happily relay through it), but B doesn't count C as one of its merchant's.
             MeshPath mesh = new MeshPath(pki.mesh("c", id -> true), at(relay.port()))) {
            refused(sender(mesh, cloud), cloud);
        }
    }

    static void rogueRelayRefused() throws Exception {
        try (Cloud cloud = new Cloud();
             // A device with a self-made certificate claiming to be B, willing to relay for anyone.
             MeshRelay rogue = new MeshRelay(pki.rogueMesh(), 0, cloud.authority(), SocketFactory.getDefault());
             MeshPath mesh = new MeshPath(pki.mesh("a", MERCHANT::contains), at(rogue.port()))) {
            refused(sender(mesh, cloud), cloud);
        }
    }

    static void notAnOpenProxy() throws Exception {
        try (Cloud cloud = new Cloud();
             MeshRelay relay = new MeshRelay(pki.mesh("b", MERCHANT::contains), 0, cloud.authority(),
                                             SocketFactory.getDefault());
             SSLSocket s = (SSLSocket) pki.mesh("a", MERCHANT::contains).getSocketFactory()
                     .createSocket("127.0.0.1", relay.port())) {
            OutputStream out = s.getOutputStream();
            out.write("CONNECT 10.0.0.1:22 HTTP/1.1\r\nHost: 10.0.0.1:22\r\n\r\n".getBytes(UTF_8));
            out.flush();
            byte[] head = new byte[12];
            int n = s.getInputStream().read(head);
            check(n > 0 && new String(head, 0, n, UTF_8).startsWith("HTTP/1.1 403"), "only the cloud is reachable");
        }
    }

    static void noNeighbour() throws Exception {
        try (Cloud cloud = new Cloud(); MeshPath mesh = new MeshPath(pki.mesh("a", MERCHANT::contains), () -> null)) {
            long start = System.nanoTime();
            try {
                sender(mesh, cloud).send(PAYLOAD);
                throw new AssertionError("sent with no neighbour");
            } catch (TransactionSender.NoPathException expected) {
                long took = ms(System.nanoTime() - start);
                check(took < 500, "gave up within 500 ms: " + took + " ms");
            }
            check(cloud.callers.isEmpty(), "nothing reached the cloud");
        }
    }

    // --- helpers ---------------------------------------------------------------------------------------------------

    /** A's own links are gone: its Wi-Fi refuses every connection, so the selector falls to the mesh. */
    static TransactionSender sender(MeshPath mesh, Cloud cloud) throws Exception {
        NetworkPath deadWifi = new NetworkPath() {
            public String name() { return "wifi"; }
            public Kind kind() { return Kind.WIFI; }
            public URLConnection open(URL url) throws IOException { throw new IOException("network unreachable"); }
        };
        PathSelector selector = new PathSelector(Arrays.asList(deadWifi, mesh));
        selector.linkLost(deadWifi);
        TransactionSender sender = new TransactionSender(selector, ChaosTest.url("https://localhost:" + cloud.port()
                + "/api/v1/transactions"), pki.cloudClient("a").getSocketFactory());
        sender.deadlineMs = 5_000;
        return sender;
    }

    static void refused(TransactionSender sender, Cloud cloud) throws Exception {
        try {
            sender.send(PAYLOAD);
            throw new AssertionError("relayed through a refused handshake");
        } catch (IOException expected) {
            check(cloud.callers.isEmpty(), "nothing reached the cloud: " + cloud.callers);
        }
    }

    static MeshPath.Neighbours at(int port) {
        return () -> new InetSocketAddress(InetAddress.getLoopbackAddress(), port);
    }

    /** One multicast group per scenario, so scenarios never hear each other. */
    static final class Lan implements AutoCloseable {
        final InetAddress group;
        final int port = 40_000 + (int) (Math.random() * 20_000);
        final List<MeshDiscovery> members = new ArrayList<>();

        Lan() throws IOException {
            group = InetAddress.getByName("239.255.25." + (1 + (int) (Math.random() * 250)));
        }

        MeshDiscovery discovery(String self) throws IOException {
            MeshDiscovery d = new MeshDiscovery(group, port, self);
            members.add(d);
            return d;
        }

        @Override
        public void close() {
            for (MeshDiscovery d : members) d.close();
        }
    }

    /** The cloud API: HTTPS, a terminal client certificate required. Records who called. */
    static final class Cloud implements AutoCloseable {
        final HttpsServer server;
        final List<String> callers = new CopyOnWriteArrayList<>();

        Cloud() throws Exception {
            final SSLContext tls = pki.server("cloud");
            server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            server.setHttpsConfigurator(new HttpsConfigurator(tls) {
                @Override
                public void configure(HttpsParameters params) {
                    SSLParameters p = tls.getDefaultSSLParameters();
                    p.setNeedClientAuth(true);
                    params.setSSLParameters(p);
                }
            });
            server.createContext("/api/v1/transactions", ex -> {
                try (InputStream in = ex.getRequestBody()) {
                    while (in.read() != -1) { /* drain */ }
                }
                X509Certificate peer = (X509Certificate) ((HttpsExchange) ex).getSSLSession().getPeerCertificates()[0];
                callers.add(MeshTls.terminalId(peer));
                byte[] body = "{\"status\":\"CAPTURED\"}".getBytes(UTF_8);
                ex.sendResponseHeaders(201, body.length);
                try (OutputStream out = ex.getResponseBody()) {
                    out.write(body);
                }
            });
            server.start();
        }

        int port() {
            return server.getAddress().getPort();
        }

        String authority() {
            return "localhost:" + port();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    /** Certificates made with the JDK's keytool. */
    static final class Pki {
        final Path dir;
        final String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();

        Pki(Path dir) throws Exception {
            this.dir = dir;
            ca("ca");
            ca("rogue-ca");
            leaf("ca", "a", "san=uri:urn:synapsepay:terminal:" + A, "eku=clientAuth");
            leaf("ca", "b", "san=uri:urn:synapsepay:terminal:" + B, "eku=clientAuth");
            leaf("ca", "c", "san=uri:urn:synapsepay:terminal:" + OTHER_MERCHANT, "eku=clientAuth");
            leaf("rogue-ca", "rogue", "san=uri:urn:synapsepay:terminal:" + B, "eku=clientAuth");
            leaf("ca", "cloud", "san=dns:localhost", "eku=serverAuth");
        }

        SSLContext mesh(String name, MeshTls.SameMerchant peers) throws Exception {
            return MeshTls.context(keys(name), PASS, cert("ca"), peers);
        }

        /** The rogue relay: its own CA's certificate, and it trusts our terminals, so only A's check can stop it. */
        SSLContext rogueMesh() throws Exception {
            return MeshTls.context(keys("rogue"), PASS, cert("ca"), id -> true);
        }

        /** A terminal's ordinary client TLS to the cloud: its key, trusting the CA for the server. */
        SSLContext cloudClient(String name) throws Exception {
            return context(name);
        }

        SSLContext server(String name) throws Exception {
            return context(name);
        }

        private SSLContext context(String name) throws Exception {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keys(name), PASS);
            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, null);
            trust.setCertificateEntry("ca", cert("ca"));
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return context;
        }

        KeyStore keys(String name) throws Exception {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream in = new FileInputStream(dir.resolve(name + ".p12").toFile())) {
                ks.load(in, PASS);
            }
            return ks;
        }

        X509Certificate cert(String name) throws Exception {
            try (FileInputStream in = new FileInputStream(dir.resolve(name + ".pem").toFile())) {
                return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
            }
        }

        private void ca(String name) throws Exception {
            run("-genkeypair", "-alias", name, "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=" + name,
                "-ext", "bc:c", "-validity", "2", "-keystore", p12(name), "-storetype", "PKCS12", "-storepass", "changeit");
            run("-exportcert", "-rfc", "-alias", name, "-file", pem(name), "-keystore", p12(name), "-storepass", "changeit");
        }

        private void leaf(String issuer, String name, String... exts) throws Exception {
            run("-genkeypair", "-alias", "key", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=" + name,
                "-validity", "2", "-keystore", p12(name), "-storetype", "PKCS12", "-storepass", "changeit");
            String csr = dir.resolve(name + ".csr").toString();
            run("-certreq", "-alias", "key", "-file", csr, "-keystore", p12(name), "-storepass", "changeit");
            List<String> gen = new ArrayList<>(Arrays.asList("-gencert", "-rfc", "-alias", issuer, "-infile", csr,
                    "-outfile", pem(name), "-validity", "2", "-keystore", p12(issuer), "-storepass", "changeit"));
            for (String ext : exts) gen.addAll(Arrays.asList("-ext", ext));
            run(gen.toArray(new String[0]));
            run("-importcert", "-noprompt", "-alias", "issuer", "-file", pem(issuer), "-keystore", p12(name),
                "-storepass", "changeit");
            run("-importcert", "-alias", "key", "-file", pem(name), "-keystore", p12(name), "-storepass", "changeit");
        }

        private String p12(String name) {
            return dir.resolve(name + ".p12").toString();
        }

        private String pem(String name) {
            return dir.resolve(name + ".pem").toString();
        }

        private void run(String... args) throws Exception {
            List<String> cmd = new ArrayList<>();
            cmd.add(keytool);
            cmd.addAll(Arrays.asList(args));
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), UTF_8);
            if (p.waitFor() != 0) throw new IOException("keytool " + args[0] + " failed: " + out);
        }
    }
}

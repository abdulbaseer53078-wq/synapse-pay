package com.synapsepay.terminal.transport;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Finding a neighbour that can relay (Step 25.1), over UDP multicast on the store's local network.
 *
 * <p>Terminals that are online announce themselves every second; every terminal keeps what it hears as a warm
 * list. So when a terminal loses its own links it already knows who can help, and picking a neighbour costs
 * nothing: no scan has to fit in the 500 ms budget. An announcement proves nothing; the mesh handshake
 * ({@link MeshTls}) is the authentication, so a forged announcement only costs one refused connection.
 *
 * <p>Android: hold a {@code WifiManager.MulticastLock} while listening. BLE discovery plugs in through
 * {@link MeshPath.Neighbours} instead (see the README).
 */
public final class MeshDiscovery implements MeshPath.Neighbours, AutoCloseable {
    public static final String MAGIC = "SYNAPSEPAY-MESH/1";
    /** A neighbour not heard from for this long is presumed gone (three missed announcements). */
    public static final long STALE_MS = 3_000;

    private static final class Seen {
        final InetSocketAddress relay;
        final long at;

        Seen(InetSocketAddress relay, long at) {
            this.relay = relay;
            this.at = at;
        }
    }

    private final InetAddress group;
    private final int port;
    private final String self;
    private final MulticastSocket socket;
    private final Map<String, Seen> neighbours = new ConcurrentHashMap<>();
    private final ScheduledExecutorService announcer = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "mesh-announce");
        t.setDaemon(true);
        return t;
    });

    /** Listens at once. {@code self}: this terminal's id, so it never picks itself. */
    @SuppressWarnings("deprecation") // joinGroup(InetAddress) and setLoopbackMode: the Java 8 / older-Android forms
    public MeshDiscovery(InetAddress group, int port, String self) throws IOException {
        this.group = group;
        this.port = port;
        this.self = self.toLowerCase();
        this.socket = new MulticastSocket(null);
        socket.setReuseAddress(true); // before bind: other apps (and terminals in a test) may share the port
        socket.bind(new InetSocketAddress(port));
        socket.setLoopbackMode(false); // false = loopback on: terminals on one host (tests) hear each other
        socket.joinGroup(group);
        MeshRelay.daemon("mesh-discovery", this::listen);
    }

    /** Announce this terminal's relay every {@code everyMs} while {@code online} says it can reach the cloud. */
    public void announce(int relayPort, final Callable<Boolean> online, long everyMs) {
        final byte[] message = (MAGIC + " " + self + " " + relayPort).getBytes(StandardCharsets.US_ASCII);
        announcer.scheduleAtFixedRate(() -> {
            try {
                if (online.call()) socket.send(new DatagramPacket(message, message.length, group, port));
            } catch (Exception ignored) {
                // the next tick tries again
            }
        }, 0, everyMs, TimeUnit.MILLISECONDS);
    }

    /** The most recently heard neighbour, or null if none was heard within {@link #STALE_MS}. */
    @Override
    public InetSocketAddress neighbour() {
        long now = System.currentTimeMillis();
        Seen best = null;
        for (Seen s : neighbours.values()) if (now - s.at < STALE_MS && (best == null || s.at > best.at)) best = s;
        return best == null ? null : best.relay;
    }

    private void listen() {
        byte[] buf = new byte[256];
        while (!socket.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);
                String[] parts = new String(packet.getData(), 0, packet.getLength(), StandardCharsets.US_ASCII).split(" ");
                if (parts.length != 3 || !parts[0].equals(MAGIC) || parts[1].equals(self)) continue;
                int relayPort = Integer.parseInt(parts[2]);
                if (relayPort < 1 || relayPort > 65_535) continue;
                neighbours.put(parts[1], new Seen(new InetSocketAddress(packet.getAddress(), relayPort),
                                                  System.currentTimeMillis()));
            } catch (IOException | RuntimeException e) {
                if (socket.isClosed()) return;
            }
        }
    }

    @Override
    public void close() {
        announcer.shutdownNow();
        socket.close();
    }
}

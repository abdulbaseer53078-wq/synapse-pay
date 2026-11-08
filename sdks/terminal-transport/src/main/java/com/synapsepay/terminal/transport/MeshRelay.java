package com.synapsepay.terminal.transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * The forwarding side of the mesh (Step 25.4): a terminal that is online relays a neighbour's connection to the
 * cloud. It is a dumb pipe. The neighbour runs its own mutual-TLS session to the cloud <em>inside</em> this
 * tunnel, so this terminal can neither read nor change the payment, and the cloud sees the neighbour's own
 * certificate: nothing about a relayed payment differs at the cloud.
 *
 * <p>What it checks: the neighbour proved it is a terminal of this merchant ({@link MeshTls}), and it asked for
 * the cloud (an HTTP CONNECT to exactly {@code cloudAuthority}). Anything else is refused, so a relay is never an
 * open proxy into the store's network or the internet.
 */
public final class MeshRelay implements AutoCloseable {
    private static final int HEADER_LIMIT = 4096;
    private static final int HANDSHAKE_MS = 2_000;
    /** A relayed transaction takes seconds; an idle tunnel is closed so a misbehaving peer can't hold sockets. */
    private static final int IDLE_MS = 60_000;

    private final SSLServerSocket server;
    private final String cloudAuthority;
    private final SocketFactory cloudSockets;

    /**
     * @param cloudAuthority "host:port" of the cloud API, the only place a neighbour may be relayed to
     * @param cloudSockets   sockets over this terminal's own internet path (Android: the active network's
     *                       {@code Network.getSocketFactory()})
     */
    public MeshRelay(SSLContext meshTls, int port, String cloudAuthority, SocketFactory cloudSockets) throws IOException {
        this.server = (SSLServerSocket) meshTls.getServerSocketFactory().createServerSocket(port);
        this.server.setNeedClientAuth(true);
        this.cloudAuthority = cloudAuthority.toLowerCase();
        this.cloudSockets = cloudSockets;
        daemon("mesh-relay", this::acceptLoop);
    }

    public int port() {
        return server.getLocalPort();
    }

    private void acceptLoop() {
        while (!server.isClosed()) {
            try {
                final SSLSocket peer = (SSLSocket) server.accept();
                daemon("mesh-relay-conn", () -> relay(peer));
            } catch (IOException e) {
                if (server.isClosed()) return;
            }
        }
    }

    private void relay(SSLSocket peer) {
        Socket cloud = null;
        try {
            peer.setSoTimeout(HANDSHAKE_MS);
            peer.startHandshake(); // MeshTls refuses anyone but this merchant's terminals
            String[] line = readHead(peer.getInputStream()).split("\r\n", 2)[0].split(" ");
            OutputStream toPeer = peer.getOutputStream();
            if (line.length != 3 || !line[0].equals("CONNECT") || !line[1].toLowerCase().equals(cloudAuthority)) {
                toPeer.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                toPeer.flush();
                return;
            }
            int colon = cloudAuthority.lastIndexOf(':');
            cloud = cloudSockets.createSocket();
            cloud.connect(new InetSocketAddress(cloudAuthority.substring(0, colon),
                                                Integer.parseInt(cloudAuthority.substring(colon + 1))), HANDSHAKE_MS);
            toPeer.write("HTTP/1.1 200 Connection established\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            toPeer.flush();
            peer.setSoTimeout(IDLE_MS);
            cloud.setSoTimeout(IDLE_MS);
            pipe(peer, cloud);
        } catch (IOException | RuntimeException e) {
            // A refused handshake or a dropped tunnel: the neighbour sees the connection close and moves on.
        } finally {
            closeQuietly(peer);
            closeQuietly(cloud);
        }
    }

    /** Copies both ways until either side closes. */
    static void pipe(final Socket a, final Socket b) throws IOException {
        daemon("mesh-pipe", () -> {
            try {
                copy(a.getInputStream(), b.getOutputStream());
            } catch (IOException ignored) {
                // the other direction notices and ends the tunnel
            } finally {
                closeQuietly(b);
            }
        });
        try {
            copy(b.getInputStream(), a.getOutputStream());
        } finally {
            closeQuietly(a);
        }
    }

    private static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[8192];
        for (int n; (n = in.read(buf)) != -1; ) {
            out.write(buf, 0, n);
            out.flush();
        }
    }

    private static String readHead(InputStream in) throws IOException {
        StringBuilder head = new StringBuilder();
        while (head.length() < 4 || !head.substring(head.length() - 4).equals("\r\n\r\n")) {
            int c = in.read();
            if (c == -1 || head.length() >= HEADER_LIMIT) throw new IOException("bad relay request");
            head.append((char) c);
        }
        return head.toString();
    }

    static void daemon(String name, Runnable task) {
        Thread t = new Thread(task, name);
        t.setDaemon(true);
        t.start();
    }

    static void closeQuietly(Socket s) {
        if (s == null) return;
        try {
            s.close();
        } catch (IOException ignored) {
            // already gone
        }
    }

    @Override
    public void close() throws IOException {
        server.close();
    }
}

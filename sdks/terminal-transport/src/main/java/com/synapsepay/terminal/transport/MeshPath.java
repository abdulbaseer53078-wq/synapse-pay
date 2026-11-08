package com.synapsepay.terminal.transport;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * Reaching the cloud through a neighbouring terminal (Step 25.3) when this terminal's own links are down.
 *
 * <p>Give it to {@link PathSelector} as the last path: it is only used when Ethernet, Wi-Fi and cellular are
 * all down, and the existing failover, probing and idempotency rules apply to it unchanged. Every request is an
 * ordinary HTTPS request with this terminal's own client certificate, sent through an HTTP CONNECT tunnel that a
 * local forwarder carries over the authenticated mesh link to the neighbour's {@link MeshRelay}. The neighbour
 * only ever sees TLS ciphertext addressed to the cloud.
 *
 * <p>Fast to fail (Step 25.5): with no neighbour in the warm list, {@link #open} fails at once; an unreachable
 * one fails within {@value #CONNECT_MS} ms. The sender then reports {@code NoPathException} and the caller
 * queues the sale offline. Use it for online authorisation only: a payment that may be approved offline anyway
 * should go straight to the offline queue.
 */
public final class MeshPath implements NetworkPath, AutoCloseable {
    /** Where the mesh finds a relay: {@link MeshDiscovery} on the LAN, or a BLE scanner on Android. */
    public interface Neighbours {
        /** A relay to try now, or null if none is known. */
        InetSocketAddress neighbour();
    }

    public static final int CONNECT_MS = 500;

    private final SSLContext meshTls;
    private final Neighbours neighbours;
    private final ServerSocket forwarder;

    public MeshPath(SSLContext meshTls, Neighbours neighbours) throws IOException {
        this.meshTls = meshTls;
        this.neighbours = neighbours;
        this.forwarder = new ServerSocket(0, 16, InetAddress.getLoopbackAddress());
        MeshRelay.daemon("mesh-forwarder", this::acceptLoop);
    }

    @Override
    public String name() {
        return "mesh";
    }

    @Override
    public Kind kind() {
        return Kind.MESH;
    }

    @Override
    public URLConnection open(URL url) throws IOException {
        if (neighbours.neighbour() == null) throw new IOException("no mesh neighbour in range");
        return url.openConnection(new Proxy(Proxy.Type.HTTP, forwarder.getLocalSocketAddress()));
    }

    private void acceptLoop() {
        while (!forwarder.isClosed()) {
            try {
                final Socket local = forwarder.accept();
                MeshRelay.daemon("mesh-forward-conn", () -> forward(local));
            } catch (IOException e) {
                if (forwarder.isClosed()) return;
            }
        }
    }

    private void forward(Socket local) {
        SSLSocket mesh = null;
        try {
            InetSocketAddress relay = neighbours.neighbour();
            if (relay == null) return;
            mesh = (SSLSocket) meshTls.getSocketFactory().createSocket();
            mesh.connect(relay, CONNECT_MS);
            mesh.setSoTimeout(CONNECT_MS);
            mesh.startHandshake(); // MeshTls: the neighbour must be this merchant's terminal
            mesh.setSoTimeout(0);
            MeshRelay.pipe(local, mesh);
        } catch (IOException e) {
            // The local HTTPS request sees its connection close and fails; the sender marks the path down.
        } finally {
            MeshRelay.closeQuietly(local);
            MeshRelay.closeQuietly(mesh);
        }
    }

    @Override
    public void close() throws IOException {
        forwarder.close();
    }
}

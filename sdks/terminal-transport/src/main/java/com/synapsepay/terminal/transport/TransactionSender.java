package com.synapsepay.terminal.transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

/**
 * Sends a transaction and gets its final answer, moving to another path when one fails (Steps 16.3 and 16.4).
 *
 * <p>The payload is copied once and every attempt sends exactly those bytes, so the cloud's idempotency check
 * (same idempotency_key and body) can only ever replay or wait, never charge twice. Never rebuild or re-encrypt
 * the payload between attempts: a different body with the same key is rejected as a conflict.
 *
 * <ul>
 *   <li>Network error (refused, reset, unreachable): the path is marked down and the same bytes go out on the
 *       next path at once.</li>
 *   <li>Connect (800 ms) or read (2 s) timeout: the same bytes go out on another path; the cloud may still be
 *       working on the first copy, in which case it answers 409 "still processing".</li>
 *   <li>409 with retryable true: the original is still with the acquirer; ask again shortly.</li>
 *   <li>The active path goes down mid-request (the OS reports the link lost): the attempt is aborted at once
 *       instead of waiting out its read timeout. This is what makes failover after a cable pull sub-second.</li>
 * </ul>
 */
public final class TransactionSender {
    /** Same request, still running at the cloud (StillProcessing). A conflicting body is retryable false. */
    private static final Pattern STILL_PROCESSING = Pattern.compile("\"retryable\"\\s*:\\s*true");

    public static final class Response {
        public final int status;
        public final byte[] body;
        public final NetworkPath path;
        /** The X-Trace-Id this payment was sent with (Step 18): quote it to support to find every log line. */
        public final String traceId;

        Response(int status, byte[] body, NetworkPath path, String traceId) {
            this.status = status;
            this.body = body;
            this.path = path;
            this.traceId = traceId;
        }
    }

    /** No final answer by the deadline. The outcome is unknown: resend the same payload later to learn it. */
    public static final class OutcomeUnknownException extends IOException {
        private static final long serialVersionUID = 1L;

        OutcomeUnknownException(String message) {
            super(message);
        }
    }

    /** Every path is down; nothing was sent on this attempt. */
    public static final class NoPathException extends IOException {
        private static final long serialVersionUID = 1L;

        NoPathException() {
            super("no network path is up");
        }
    }

    private final PathSelector selector;
    private final URL url;
    private final SSLSocketFactory tls; // the terminal's mTLS client certificate; null for plain HTTP (tests)
    public int connectTimeoutMs = 800;
    public int readTimeoutMs = 2_000;
    public int stillProcessingDelayMs = 250;
    /** Longer than the cloud's own acquirer timeout (15 s), so a slow approval is still collected. */
    public long deadlineMs = 30_000;

    private volatile Attempt current;

    private static final class Attempt {
        final NetworkPath path;
        final HttpURLConnection connection;

        Attempt(NetworkPath path, HttpURLConnection connection) {
            this.path = path;
            this.connection = connection;
        }
    }

    public TransactionSender(PathSelector selector, URL transactionsUrl, SSLSocketFactory tls) {
        this.selector = selector;
        this.url = transactionsUrl;
        this.tls = tls;
        selector.addListener((previous, active) -> {
            Attempt a = current;
            if (a != null && a.path == previous) a.connection.disconnect(); // its path just failed: give up on it now
        });
    }

    /** Sends {@code payload} (the serialized TransactionRequest) until the cloud gives a final answer. */
    public Response send(byte[] payload) throws IOException {
        final byte[] body = payload.clone();
        // One trace id per payment, the same on every path and retry, so the cloud's logs join them into one trace.
        final String traceId = UUID.randomUUID().toString().replace("-", "");
        final long deadline = System.nanoTime() + deadlineMs * 1_000_000;
        NetworkPath path = selector.active();
        while (true) {
            if (path == null) throw new NoPathException();
            if (System.nanoTime() > deadline) {
                throw new OutcomeUnknownException("no final answer within " + deadlineMs + " ms; resend later");
            }
            try {
                Response r = post(path, body, traceId);
                if (r.status == 409 && STILL_PROCESSING.matcher(new String(r.body, "UTF-8")).find()) {
                    sleep(stillProcessingDelayMs);
                    path = selector.active();
                    continue;
                }
                return r;
            } catch (SocketTimeoutException e) {
                NetworkPath other = selector.fallback(path); // maybe silently dead, maybe just slow: try another way
                path = other != null ? other : selector.active();
            } catch (IOException e) {
                selector.sendFailed(path);
                path = selector.active();
            }
        }
    }

    private Response post(NetworkPath path, byte[] body, String traceId) throws IOException {
        HttpURLConnection c = (HttpURLConnection) path.open(url);
        if (tls != null && c instanceof HttpsURLConnection) ((HttpsURLConnection) c).setSSLSocketFactory(tls);
        c.setRequestMethod("POST");
        c.setConnectTimeout(connectTimeoutMs);
        c.setReadTimeout(readTimeoutMs);
        c.setDoOutput(true);
        c.setFixedLengthStreamingMode(body.length);
        c.setRequestProperty("Content-Type", "application/json");
        c.setRequestProperty("X-Trace-Id", traceId);
        current = new Attempt(path, c);
        try {
            if (!selector.isUp(path)) throw new IOException("path went down"); // lost while we were opening it
            try (OutputStream out = c.getOutputStream()) {
                out.write(body);
            }
            int status = c.getResponseCode();
            byte[] response;
            try (InputStream in = status < 400 ? c.getInputStream() : c.getErrorStream()) {
                response = Io.readAll(in);
            }
            return new Response(status, response, path, traceId);
        } finally {
            current = null;
        }
    }

    private static void sleep(long ms) throws IOException {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted", e);
        }
    }
}

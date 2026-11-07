package com.synapsepay.android;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * The few client-secret endpoints a merchant app calls. Network failures and 5xx answers are retried up to 3 times
 * with backoff; that's safe because confirming an intent twice never charges twice. Blocking: call it off the
 * main thread (the Kotlin {@link SynapsePay} facade does).
 */
public final class SynapsePayApi {
    public static final class Response {
        public final int status;
        public final String body;

        Response(int status, String body) {
            this.status = status;
            this.body = body;
        }

        public boolean ok() {
            return status >= 200 && status < 300;
        }
    }

    private final String apiBase;
    private final int timeoutMs;

    public SynapsePayApi(String apiBase) {
        this(apiBase, 30_000);
    }

    public SynapsePayApi(String apiBase, int timeoutMs) {
        this.apiBase = apiBase.replaceAll("/+$", "");
        this.timeoutMs = timeoutMs;
    }

    public String apiBase() {
        return apiBase;
    }

    /** pi_..._secret_... → pi_... */
    public static String intentIdOf(String clientSecret) {
        int at = clientSecret.indexOf("_secret_");
        String id = at > 0 ? clientSecret.substring(0, at) : "";
        if (!id.matches("pi_[0-9a-f]{32}")) throw new IllegalArgumentException("That isn't a payment intent client_secret.");
        return id;
    }

    public Response checkoutKey() throws IOException {
        return send("GET", "/api/v1/checkout/key", null);
    }

    public Response retrieve(String clientSecret) throws IOException {
        return send("GET", "/api/v1/payment_intents/" + intentIdOf(clientSecret) + "?client_secret="
                + URLEncoder.encode(clientSecret, "UTF-8"), null);
    }

    public Response confirm(String clientSecret, String encryptedCard, String encryptedCvv, String expiryMmYy,
                            String network) throws IOException {
        String body = "{\"client_secret\":" + quote(clientSecret) + ",\"payment_method\":\"CARD\",\"card\":{"
                + "\"encrypted_card_data\":" + quote(encryptedCard) + ",\"encrypted_cvv\":" + quote(encryptedCvv)
                + ",\"card_expiry\":" + quote(expiryMmYy) + ",\"card_network\":" + quote(network) + "}}";
        return send("POST", "/api/v1/payment_intents/" + intentIdOf(clientSecret) + "/confirm", body);
    }

    private Response send(String method, String path, String body) throws IOException {
        IOException last = null;
        Response lastResponse = null;
        for (int attempt = 0; attempt < 4; attempt++) {
            if (attempt > 0) sleep(400L << (attempt - 1));
            try {
                Response r = once(method, path, body);
                if (r.status < 500) return r;
                lastResponse = r;
            } catch (IOException e) {
                last = e;
            }
        }
        if (lastResponse != null) return lastResponse;
        throw last;
    }

    private Response once(String method, String path, String body) throws IOException {
        HttpURLConnection c = (HttpURLConnection) URI.create(apiBase + path).toURL().openConnection();
        try {
            c.setRequestMethod(method);
            c.setConnectTimeout(timeoutMs);
            c.setReadTimeout(timeoutMs);
            c.setUseCaches(false);
            c.setRequestProperty("accept", "application/json");
            c.setRequestProperty("user-agent", "synapsepay-android/0.1.0");
            if (body != null) {
                c.setDoOutput(true);
                c.setRequestProperty("content-type", "application/json");
                try (OutputStream out = c.getOutputStream()) {
                    out.write(body.getBytes(StandardCharsets.UTF_8));
                }
            }
            int status = c.getResponseCode();
            InputStream in = status < 400 ? c.getInputStream() : c.getErrorStream();
            return new Response(status, in == null ? "" : read(in));
        } finally {
            c.disconnect();
        }
    }

    private static String read(InputStream in) throws IOException {
        try (InputStream s = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            for (int n; (n = s.read(buf)) > 0; ) out.write(buf, 0, n);
            return out.toString("UTF-8");
        }
    }

    /** JSON string literal. */
    static String quote(String s) {
        StringBuilder out = new StringBuilder("\"");
        for (char ch : s.toCharArray()) {
            if (ch == '"' || ch == '\\') out.append('\\').append(ch);
            else if (ch < 0x20) out.append(String.format("\\u%04x", (int) ch));
            else out.append(ch);
        }
        return out.append('"').toString();
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

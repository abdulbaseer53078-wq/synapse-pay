package com.synapsepay.terminal.transport;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Proves each path actually reaches the cloud (Step 16.1): the OS can say "connected" to a router with no
 * internet. A {@code HEAD} to the gateway's health endpoint, with the connect timeout transactions use.
 *
 * <p>The active path and any DOWN path (to notice recovery) are probed every tick; healthy standby paths only
 * every {@code standbyEvery} ticks, because standby is usually metered cellular.
 */
public final class HealthProber implements AutoCloseable {
    private final PathSelector selector;
    private final URL healthUrl;
    private final int timeoutMs;
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "synapsepay-path-prober");
        t.setDaemon(true);
        return t;
    });
    private long tick;

    public HealthProber(PathSelector selector, URL healthUrl, int timeoutMs) {
        this.selector = selector;
        this.healthUrl = healthUrl;
        this.timeoutMs = timeoutMs;
    }

    /** Probes every {@code intervalMs} (default design: 5 s), standby paths every {@code standbyEvery} ticks. */
    public void start(long intervalMs, int standbyEvery) {
        timer.scheduleWithFixedDelay(() -> {
            NetworkPath active = selector.active();
            for (NetworkPath p : selector.paths()) {
                if (p == active || !selector.isUp(p) || tick % standbyEvery == 0) selector.probeResult(p, probe(p));
            }
            tick++;
        }, 0, intervalMs, TimeUnit.MILLISECONDS);
    }

    /** One probe: true if the gateway answered 2xx over this path in time. */
    public boolean probe(NetworkPath path) {
        try {
            HttpURLConnection c = (HttpURLConnection) path.open(healthUrl);
            c.setRequestMethod("HEAD");
            c.setConnectTimeout(timeoutMs);
            c.setReadTimeout(timeoutMs);
            int status = c.getResponseCode();
            try (InputStream in = status < 400 ? c.getInputStream() : c.getErrorStream()) {
                Io.readAll(in); // drain, so the keep-alive connection is reused for the next probe
            }
            return status / 100 == 2;
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    @Override
    public void close() {
        timer.shutdownNow();
    }
}

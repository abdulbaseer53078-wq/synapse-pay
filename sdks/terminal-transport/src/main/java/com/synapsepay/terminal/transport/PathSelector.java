package com.synapsepay.terminal.transport;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Chooses the path transactions use (Step 16.2): the highest-priority path that is up and not weak.
 *
 * <p>Paths are given in priority order, cheapest first (Ethernet / Wi-Fi, then cellular), so the terminal goes
 * back to Wi-Fi as soon as it is healthy again. A path goes DOWN at once when the OS reports the link lost or a
 * send fails at the network level, or after {@value #FAILURES_TO_DEMOTE} failed probes in a row; it comes back
 * only after {@value #SUCCESSES_TO_RESTORE} good probes in a row, so a flapping router can't bounce traffic.
 * A Wi-Fi signal below {@value #WEAK_DBM} dBm marks the path weak (avoided while a better one is up) until it
 * recovers above {@value #RECOVERED_DBM} dBm: the gap stops it flapping around a single threshold.
 *
 * <p>shortcut: no tertiary offline queue: with every path down, {@link #active()} is null and sends fail fast;
 * hand those to the offline queue once it exists.
 */
public final class PathSelector {
    public static final int FAILURES_TO_DEMOTE = 3;
    public static final int SUCCESSES_TO_RESTORE = 3;
    public static final int WEAK_DBM = -80;
    public static final int RECOVERED_DBM = -70;

    /** Told when the active path changes, e.g. to show the cashier a 4G icon. {@code active} null: no path. */
    public interface Listener {
        void onActivePathChanged(NetworkPath previous, NetworkPath active);
    }

    private static final class Health {
        boolean up = true;
        boolean weak;
        int failures;
        int successes;
    }

    private final List<NetworkPath> paths;
    private final Map<NetworkPath, Health> health = new HashMap<>();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    private NetworkPath active;

    /** {@code paths} in priority order. All start up; probes and OS events correct that. */
    public PathSelector(List<NetworkPath> paths) {
        if (paths.isEmpty()) throw new IllegalArgumentException("at least one path");
        this.paths = Collections.unmodifiableList(new ArrayList<>(paths));
        for (NetworkPath p : this.paths) health.put(p, new Health());
        active = this.paths.get(0);
    }

    public void addListener(Listener listener) {
        listeners.add(listener);
    }

    public synchronized NetworkPath active() {
        return active;
    }

    public synchronized List<NetworkPath> paths() {
        return paths;
    }

    public synchronized boolean isUp(NetworkPath path) {
        return health.get(path).up;
    }

    /** The best usable path other than {@code avoid}, or null: where to resend after {@code avoid} timed out. */
    public synchronized NetworkPath fallback(NetworkPath avoid) {
        for (NetworkPath p : paths) if (p != avoid && usable(p)) return p;
        for (NetworkPath p : paths) if (p != avoid && health.get(p).up) return p;
        return null;
    }

    /** The OS reports the link gone (Android: ConnectivityManager.NetworkCallback.onLost). */
    public void linkLost(NetworkPath path) {
        update(path, h -> { h.up = false; h.successes = 0; });
    }

    /** A send on this path failed at the network level (refused, reset, unreachable). */
    public void sendFailed(NetworkPath path) {
        linkLost(path);
    }

    public void probeResult(NetworkPath path, boolean ok) {
        update(path, h -> {
            if (ok) {
                h.failures = 0;
                if (!h.up && ++h.successes >= SUCCESSES_TO_RESTORE) h.up = true;
            } else {
                h.successes = 0;
                if (h.up && ++h.failures >= FAILURES_TO_DEMOTE) h.up = false;
            }
        });
    }

    /** Wi-Fi signal strength (Android: WifiInfo.getRssi()). */
    public void signal(NetworkPath path, int dBm) {
        update(path, h -> h.weak = dBm < WEAK_DBM || (h.weak && dBm < RECOVERED_DBM));
    }

    private boolean usable(NetworkPath p) {
        Health h = health.get(p);
        return h.up && !h.weak;
    }

    private interface Change {
        void apply(Health h);
    }

    private void update(NetworkPath path, Change change) {
        NetworkPath previous, next;
        synchronized (this) {
            Health h = health.get(path);
            if (h == null) throw new IllegalArgumentException("unknown path " + path.name());
            change.apply(h);
            previous = active;
            next = null;
            for (NetworkPath p : paths) if (usable(p)) { next = p; break; }
            if (next == null) for (NetworkPath p : paths) if (health.get(p).up) { next = p; break; } // weak beats none
            active = next;
        }
        if (previous != next) for (Listener l : listeners) l.onActivePathChanged(previous, next); // outside the lock
    }
}

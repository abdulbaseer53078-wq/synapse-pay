package com.synapsepay.terminal.transport;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

/**
 * One way out of the terminal: an Ethernet, Wi-Fi or cellular interface.
 *
 * <p>On Android, wrap a {@code android.net.Network} and return {@code network.openConnection(url)}, which binds
 * the connection to that interface (see the README). Tests use local proxies instead.
 */
public interface NetworkPath {
    /** MESH: a neighbouring terminal's connection ({@link MeshPath}, Step 25), always the lowest priority. */
    enum Kind { ETHERNET, WIFI, CELLULAR, MESH }

    String name();

    Kind kind();

    /** Opens a connection to {@code url} that goes out over this path only. */
    URLConnection open(URL url) throws IOException;
}

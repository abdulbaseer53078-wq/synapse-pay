package com.synapsepay.terminal.transport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/** Java 8 / older-Android stand-ins (InputStream.readAllBytes needs Android API 33). */
final class Io {
    private Io() {}

    static byte[] readAll(InputStream in) throws IOException {
        if (in == null) return new byte[0];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        for (int n; (n = in.read(buf)) != -1; ) out.write(buf, 0, n);
        return out.toByteArray();
    }
}

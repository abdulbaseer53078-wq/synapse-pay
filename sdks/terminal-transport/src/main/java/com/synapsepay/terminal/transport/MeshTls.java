package com.synapsepay.terminal.transport;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * The handshake between two terminals (Step 25.2): both sides show their registration certificate, and each
 * accepts the other only if it chains to the Synapse Pay terminal CA <em>and</em> names a terminal of the same
 * merchant. Anything else (another merchant's terminal, a laptop with a self-made certificate) is refused before
 * a byte of payment traffic moves.
 *
 * <p>Terminal certificates are issued for client authentication only, so the usual TLS server check (extended
 * key usage serverAuth) would refuse every neighbour. This trust manager validates the chain itself (PKIX, no
 * EKU check) and then the identity, which is the check that matters here.
 *
 * <p>shortcut: no revocation check (there may be no internet to fetch a CRL); the same-merchant list comes from
 * the cloud's registry, which only lists ACTIVE terminals, so refresh it whenever the terminal is online.
 */
public final class MeshTls {
    /** The merchant's active terminals, by terminal id (from the cloud registry, cached on the terminal). */
    public interface SameMerchant {
        boolean contains(String terminalId);
    }

    private static final String URI_PREFIX = "urn:synapsepay:terminal:";
    private static final int SAN_URI = 6;

    private MeshTls() {}

    /** {@code key}: this terminal's registration key and certificate chain. */
    public static SSLContext context(KeyStore key, char[] password, X509Certificate ca, SameMerchant peers)
            throws GeneralSecurityException {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(key, password);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), new TrustManager[] {new Trust(ca, peers)}, null);
        return context;
    }

    /** The terminal id in a certificate's URI SAN, or null. */
    public static String terminalId(X509Certificate cert) {
        Collection<List<?>> names;
        try {
            names = cert.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            return null;
        }
        if (names == null) return null;
        for (List<?> name : names) {
            Object value = name.get(1);
            if (((Integer) name.get(0)) == SAN_URI && value instanceof String && ((String) value).startsWith(URI_PREFIX)) {
                return ((String) value).substring(URI_PREFIX.length()).toLowerCase();
            }
        }
        return null;
    }

    private static final class Trust implements X509TrustManager {
        private final X509Certificate ca;
        private final SameMerchant peers;

        Trust(X509Certificate ca, SameMerchant peers) {
            this.ca = ca;
            this.peers = peers;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            check(chain);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            check(chain);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[] {ca};
        }

        private void check(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length == 0) throw new CertificateException("no certificate");
            try {
                PKIXParameters params = new PKIXParameters(Collections.singleton(new TrustAnchor(ca, null)));
                params.setRevocationEnabled(false);
                List<X509Certificate> path = Arrays.asList(chain);
                if (path.size() > 1 && path.get(path.size() - 1).equals(ca)) path = path.subList(0, path.size() - 1);
                CertPathValidator.getInstance("PKIX")
                        .validate(CertificateFactory.getInstance("X.509").generateCertPath(path), params);
            } catch (GeneralSecurityException e) {
                throw new CertificateException("not issued by the terminal CA", e);
            }
            String id = terminalId(chain[0]);
            if (id == null || !peers.contains(id)) throw new CertificateException("not a terminal of this merchant");
        }
    }
}

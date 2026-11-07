package com.synapsepay.android;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts card data to Synapse Pay's checkout key, exactly as the web card frame does (envelope "sp2"):
 * ephemeral ECDH P-256, HKDF-SHA256 (salt = ephemeral public key, info = "synapsepay/checkout/v1/" + usage),
 * AES-256-GCM with the usage as additional data. Only the card service's HSM can decrypt it.
 *
 * Plain Java with only JDK/Android crypto, so it runs on every Android version the SDK supports and can be
 * tested on any JVM.
 */
public final class CheckoutCrypto {
    private static final SecureRandom RANDOM = new SecureRandom();
    private final ECPublicKey checkoutKey;

    /** @param x base64url X coordinate from the checkout key JWK; @param y likewise Y. */
    public CheckoutCrypto(String x, String y) throws GeneralSecurityException {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        ECPoint point = new ECPoint(new BigInteger(1, b64urlDecode(x)), new BigInteger(1, b64urlDecode(y)));
        this.checkoutKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
    }

    /** Returns the sp2 envelope for `plaintext` (card number digits: usage "data"; security code: "cvv"). */
    public String seal(String plaintext, String usage) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
        KeyPair ephemeral = generator.generateKeyPair();
        byte[] epk = uncompressed((ECPublicKey) ephemeral.getPublic());

        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(ephemeral.getPrivate());
        agreement.doPhase(checkoutKey, true);
        byte[] shared = agreement.generateSecret();
        byte[] key = hkdfSha256(shared, epk, ("synapsepay/checkout/v1/" + usage).getBytes(StandardCharsets.UTF_8));
        Arrays.fill(shared, (byte) 0);

        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(usage.getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        Arrays.fill(key, (byte) 0);

        byte[] body = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, body, 0, nonce.length);
        System.arraycopy(ciphertext, 0, body, nonce.length, ciphertext.length);
        return "sp2." + b64url(epk) + "." + b64url(body);
    }

    /** 65-byte uncompressed SEC1 point: 0x04 || X || Y. */
    static byte[] uncompressed(ECPublicKey key) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        copyFixed(key.getW().getAffineX(), out, 1);
        copyFixed(key.getW().getAffineY(), out, 33);
        return out;
    }

    private static void copyFixed(BigInteger value, byte[] out, int offset) {
        byte[] raw = value.toByteArray();
        int start = raw.length > 32 ? raw.length - 32 : 0;
        int length = raw.length - start;
        System.arraycopy(raw, start, out, offset + 32 - length, length);
    }

    /** RFC 5869 with SHA-256, 32 bytes of output. */
    static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(info);
        mac.update((byte) 1);
        return mac.doFinal(); // T(1) is exactly 32 bytes
    }

    static String b64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static byte[] b64urlDecode(String s) {
        return Base64.getUrlDecoder().decode(s);
    }
}

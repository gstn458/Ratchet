package jca;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;

class Jca {
    private static final String SIG = "SHA1withRSA";
    private static final String KEX = "ECDH";
    private String mutable = "MD5";

    void run(String dynamic) throws Exception {
        KeyPairGenerator.getInstance("RSA");
        KeyPairGenerator.getInstance("EC");
        Signature.getInstance(SIG);
        Signature.getInstance("SHA256withECDSA", "BC");
        java.security.MessageDigest.getInstance("SHA-1");
        MessageDigest.getInstance("md5");
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        Cipher.getInstance("DESede/CBC/PKCS5Padding");
        Cipher.getInstance("AES/GCM/NoPadding");
        KeyAgreement.getInstance(KEX);
        Mac.getInstance("HmacSHA1");
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        Signature.getInstance("SHA512withRSA");
        KeyPairGenerator.getInstance("EdDSA");
        MessageDigest.getInstance(dynamic);
        MessageDigest.getInstance(mutable);
        mutable = "SHA-256";
        Other.getInstance("RSA");
    }
}

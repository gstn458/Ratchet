package keys;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.crypto.KeyGenerator;

class KeyGen {
    private static final int DSA_BITS = 1024;
    private static final String CURVE = "secp384r1";

    void rsa() throws Exception {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
    }

    void rsaWithRandom() throws Exception {
        KeyPairGenerator strong = KeyPairGenerator.getInstance("RSA");
        strong.initialize(4096, new SecureRandom());
    }

    void rsaSpec() throws Exception {
        KeyPairGenerator specGen = KeyPairGenerator.getInstance("RSA");
        specGen.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
    }

    void dsa() throws Exception {
        KeyPairGenerator dsaGen = KeyPairGenerator.getInstance("DSA");
        dsaGen.initialize(DSA_BITS);
    }

    void ec() throws Exception {
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(new ECGenParameterSpec(CURVE));
    }

    void ecBySize() throws Exception {
        KeyPairGenerator sized = KeyPairGenerator.getInstance("EC");
        sized.initialize(256);  // the provider picks the curve: not claimed
    }

    void aes() throws Exception {
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(256);
    }

    void reused(int bits) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(bits);  // not a literal: not claimed
    }

    void reusedAgain() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024);  // "gen" is declared twice in this file: ambiguous, not claimed
    }
}

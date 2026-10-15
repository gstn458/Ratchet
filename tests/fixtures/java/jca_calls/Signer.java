package jca;

import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

class Signer {
    void sign() throws Exception {
        KeyPairGenerator.getInstance("EC");
        Signature.getInstance("SHA256withECDSA");
    }
}

package jwt;

import java.security.Signature;

enum Algorithm {
    RS256("SHA256withRSA"),
    RS1("SHA1withRSA"),
    PS256("RSASSA-PSS"),
    ES256("SHA256withECDSA"),
    LEGACY("DESede/CBC/PKCS5Padding");

    final String jcaName;

    Algorithm(String jcaName) {
        this.jcaName = jcaName;
    }

    Signature signer() throws Exception {
        return Signature.getInstance(jcaName);
    }
}

class Keys {
    static final String CURVE = "secp256r1";
    String kty = "RSA";            // a JWK key type: too short to claim
    String hash = "MD5";           // likewise
    String message = "use SHA256withRSA for new keys";  // a sentence, not a name
    String agreement = "X25519";

    Object direct() throws Exception {
        return Signature.getInstance("SHA256withRSA");  // a call site, counted once
    }
}

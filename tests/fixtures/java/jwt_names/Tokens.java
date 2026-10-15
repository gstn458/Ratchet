package tokens;

class Tokens {
    static final String DEFAULT = "RS256";
    String[] allowed = {"ES256", "PS512", "Ed25519"};
    String wrap = "RSA-OAEP-256";
}

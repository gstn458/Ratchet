package app;

import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.interfaces.DHPublicKey;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.digests.SHA1Digest;
import static java.security.spec.RSAKeyGenParameterSpec.F4;
import org.bouncycastle.crypto.params.*;
import java.util.List;

// import java.security.interfaces.RSAKey;  (commented out: not an import)
class Keys {
    String note = "import java.security.interfaces.DSAKey;";
}

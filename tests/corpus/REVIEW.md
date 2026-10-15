# Label review sheet

Every false positive, and a random 10% of true positives (seed 20261014,
regenerated from the committed labels by `review.py`). Change a verdict in
`labels/<name>.json` and say why in the commit message.

## False positives (1)

- **go-jose** `asymmetric.go:395:ECDSA`
  `priv, err := ecdsa.GenerateKey(ctx.publicKey.Curve, randReader)`
  fp: read by hand: ecdsa.GenerateKey makes the ephemeral key for ECDH-ES in genKey(); the agreement is in cipher/ecdh_es.go. ECDSA usage label is wrong

## True positives, random sample (104 of 1037)

- **age** `agessh/agessh.go:212:X25519`
  `ourPublicKey, err := curve25519.X25519(ephemeral, curve25519.Basepoint)`
  tp: rule go-package-call: curve25519.X25519-family call, golang.org/x/crypto/curve25519 imported, name not shadowed
- **age** `agessh/agessh.go:217:X25519`
  `sharedSecret, err := curve25519.X25519(ephemeral, r.theirPublicKey)`
  tp: rule go-package-call: curve25519.X25519-family call, golang.org/x/crypto/curve25519 imported, name not shadowed
- **age** `agessh/agessh.go:329:X25519`
  `sharedSecret, err := curve25519.X25519(i.secretKey, publicKey)`
  tp: rule go-package-call: curve25519.X25519-family call, golang.org/x/crypto/curve25519 imported, name not shadowed
- **age** `agessh/agessh.go:36:SHA-256`
  `h := sha256.Sum256(pk.Marshal())`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **age** `agessh/agessh.go:81:RSA`
  `wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,`
  tp: rule go-package-call: rsa.EncryptOAEP, crypto/rsa imported, name not shadowed
- **age** `agessh/agessh_test.go:49:RSA-2048`
  `pk, err := rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **ansible** `test/integration/targets/ssh_agent/action_plugins/ssh_keygen.py:22:Ed25519`
  `private_key = Ed25519PrivateKey.generate()`
  tp: read by hand: call into the named algorithm confirmed in context
- **caddy** `caddytest/integration/acmeserver_test.go:105:ECDSA`
  `certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **caddy** `caddytest/integration/ech_test.go:107:X25519`
  `key, err := ecdh.X25519().GenerateKey(rand.Reader)`
  tp: rule go-package-call: ecdh.X25519-family call, crypto/ecdh imported, name not shadowed
- **certbot** `acme/src/acme/_internal/tests/crypto_util_test.py:120:RSA-2048`
  `self.privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)`
  tp: read by hand: EC keys sign certificates or CSRs (actual use: ECDSA); RSA keys are account and certificate keys
- **certbot** `certbot/src/certbot/_internal/tests/san_test.py:89:EC-SECP256R1`
  `key = ec.generate_private_key(ec.SECP256R1())`
  tp: read by hand: EC keys sign certificates or CSRs (actual use: ECDSA); RSA keys are account and certificate keys
- **certbot** `certbot/src/certbot/crypto_util.py:264:RSA`
  `key = rsa.generate_private_key(public_exponent=65537, key_size=bits)`
  tp: read by hand: EC keys sign certificates or CSRs (actual use: ECDSA); RSA keys are account and certificate keys
- **cfssl** `api/revoke/revoke_test.go:129:RSA-2048`
  `privKey, err := rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **cfssl** `ocsp/responder.go:405:SHA-256`
  `responseHash := sha256.Sum256(ocspResponse)`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **cfssl** `scan/crypto/md5/example_test.go:23:MD5`
  `fmt.Printf("%x", md5.Sum(data))`
  tp: rule go-package-call: md5.Sum, crypto/md5 imported, name not shadowed
- **cfssl** `scan/crypto/rsa/pss_test.go:60:SHA-1`
  `hash := sha1.New()`
  tp: rule go-package-call: sha1.New, crypto/sha1 imported, name not shadowed
- **cfssl** `scan/crypto/tls/cipher_suites.go:160:AES`
  `aes, err := aes.NewCipher(key)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **cfssl** `scan/crypto/tls/generate_cert.go:92:Ed25519`
  `_, priv, err = ed25519.GenerateKey(rand.Reader)`
  tp: rule go-package-call: ed25519.GenerateKey, crypto/ed25519 imported, name not shadowed
- **cfssl** `scan/crypto/tls/key_agreement.go:101:MD5`
  `hmd5 := md5.New()`
  tp: rule go-package-call: md5.New, crypto/md5 imported, name not shadowed
- **forge** `lib/pkcs1.js:194:SHA-1`
  `md = forge.md.sha1.create();`
  tp: read by hand: forge.md.<hash>.create() with forge = require('./forge') in forge's own library
- **forge** `lib/pkcs12.js:445:SHA-256`
  `md = forge.md.sha256.create();`
  tp: read by hand: forge.md.<hash>.create() with forge = require('./forge') in forge's own library
- **forge** `lib/x509.js:709:SHA-256`
  `return forge.md.sha256.create();`
  tp: read by hand: forge.md.<hash>.create() with forge = require('./forge') in forge's own library
- **go-jose** `cipher/key_wrap_test.go:156:AES`
  `block, _ := aes.NewCipher(kek)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **go-jose** `cipher/key_wrap_test.go:170:AES`
  `block, _ := aes.NewCipher(kek)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **go-jose** `cryptosigner/cryptosigner_test.go:119:Ed25519`
  `ver, sig, _ = ed25519.GenerateKey(rand.Reader)`
  tp: rule go-package-call: ed25519.GenerateKey, crypto/ed25519 imported, name not shadowed
- **go-jose** `cryptosigner/cryptosigner_test.go:129:ECDSA`
  `key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **go-jose** `cryptosigner/cryptosigner_test.go:168:ECDSA`
  `p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **go-jose** `jwk_test.go:425:SHA-256`
  `sha256sum := sha256.Sum256(nil)`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **go-jose** `jwk_test.go:913:Ed25519`
  `_, otherPrivateKey, err := ed25519.GenerateKey(rand.Reader)`
  tp: rule go-package-call: ed25519.GenerateKey, crypto/ed25519 imported, name not shadowed
- **go-jose** `signing_test.go:446:ECDSA`
  `key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **go-jose** `symmetric.go:453:AES`
  `block, err := aes.NewCipher(key)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **golang-jwt** `ecdsa.go:83:ECDSA`
  `if verifystatus := ecdsa.Verify(ecdsaKey, hasher.Sum(nil), r, s); verifystatus {`
  tp: rule go-package-call: ecdsa.Verify, crypto/ecdsa imported, name not shadowed
- **paramiko** `paramiko/kex_curve25519.py:45:X25519`
  `self.key = X25519PrivateKey.generate()`
  tp: read by hand: call into the named algorithm confirmed in context
- **pyjwt** `jwt/algorithms.py:929:RSA`
  `padding.PSS(`
  tp: rule py-cryptography-object: padding.PSS(), padding imported once from cryptography.hazmat.primitives.asymmetric, bound nowhere else
- **python-jose** `jose/backends/cryptography_backend.py:209:SHA-1`
  `RSA_OAEP = padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)`
  tp: rule py-cryptography-object: hashes.SHA1(), hashes imported once from cryptography.hazmat.primitives, bound nowhere else
- **python-jose** `tests/algorithms/test_EC.py:111:EC`
  `CryptographyEc.generate_private_key(mapping[algorithm](), backend=CryptographyBackend()), algorithm`
  tp: read by hand: EC, usage undetermined: key used for JWS ES* signing elsewhere
- **scapy** `scapy/layers/inet6.py:2398:MD5`
  `h = md5(record.encode("utf8"))`
  tp: rule py-hashlib-import: md5 imported from hashlib
- **scapy** `scapy/layers/msrpce/msnrpc.py:233:MD5`
  `h = hmac.HMAC(SessionKey, hashes.MD5())`
  tp: read by hand: hashes from cryptography.hazmat.primitives, rebound only to None when cryptography is missing; used in HMAC
- **scapy** `scapy/layers/radius.py:1341:MD5`
  `radius_mac = hashlib.md5(data + shared_secret)`
  tp: rule py-hashlib: hashlib.md5() call
- **scapy** `scapy/layers/tls/crypto/groups.py:526:EC`
  `return ec.generate_private_key(curve, default_backend())`
  tp: read by hand: EC, usage undetermined: TLS key-exchange group key (actual use: ECDH)
- **scapy** `scapy/libs/rfc3961.py:897:3DES`
  `decrepit_algorithms.TripleDES(key), modes.CBC(b"\0" * 8)`
  tp: read by hand: decrepit_algorithms is cryptography's decrepit ciphers.algorithms, falling back to primitives algorithms on older versions; either way the named cipher
- **step-ca** `acme/challenge.go:1809:Ed25519`
  `if !ed25519.Verify(pub, []byte(keyAuth), sig) {`
  tp: rule go-package-call: ed25519.Verify, crypto/ed25519 imported, name not shadowed
- **step-ca** `acme/challenge_test.go:2232:SHA-256`
  `h := sha256.Sum256([]byte(expKeyAuth))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `acme/challenge_test.go:3240:SHA-256`
  `expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `api/ssh_test.go:39:ECDSA`
  `priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `authority/authorize_test.go:1443:Ed25519`
  `_, otherSigner, err := ed25519.GenerateKey(rand.Reader)`
  tp: rule go-package-call: ed25519.GenerateKey, crypto/ed25519 imported, name not shadowed
- **step-ca** `authority/provisioner/azure_test.go:62:SHA-256`
  `sum := sha256.Sum256([]byte("/subscriptions/subscriptionID/resourceGroups/resourceGroup/providers/Microsoft.Compute/virtualMachines/virtualM`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `authority/provisioner/nebula_test.go:60:Ed25519`
  `pub, priv, err := ed25519.GenerateKey(rand.Reader)`
  tp: rule go-package-call: ed25519.GenerateKey, crypto/ed25519 imported, name not shadowed
- **step-ca** `authority/ssh_test.go:325:ECDSA`
  `signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `cas/softcas/softcas_test.go:414:RSA-2048`
  `signer, err := rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **step-ca** `cas/softcas/softcas_test.go:475:ECDSA`
  `rootSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `scep/authority_test.go:140:RSA-2048`
  `return rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **twisted** `src/twisted/conch/ssh/keys.py:1033:MD5`
  `[binascii.hexlify(x) for x in iterbytes(md5(self.blob()).digest())]`
  tp: rule py-hashlib-import: md5 imported from hashlib
- **twisted** `src/twisted/conch/ssh/keys.py:1897:RSA`
  `privateKey = rsa.generate_private_key(public_exponent=65537, key_size=keySize)`
  tp: read by hand: call into the named algorithm confirmed in context
- **twisted** `src/twisted/conch/test/test_keys.py:1502:RSA`
  `common.getNS(signature)[0], data, padding.PKCS1v15(), hashes.SHA1()`
  tp: rule py-cryptography-object: padding.PKCS1v15(), padding imported once from cryptography.hazmat.primitives.asymmetric, bound nowhere else
- **twisted** `src/twisted/test/test_sslverify.py:3526:EC-SECP256R1`
  `key = ec.generate_private_key(ec.SECP256R1())`
  tp: read by hand: EC, usage undetermined: signs a CSR (actual use: ECDSA)
- **twisted** `src/twisted/words/test/test_jabberclient.py:201:SHA-1`
  `self.assertEqual(sha1(b"12345secret").hexdigest(), str(iq.query.digest))`
  tp: rule py-hashlib-import: sha1 imported from hashlib
- **twisted** `src/twisted/words/test/test_jabbercomponent.py:57:SHA-1`
  `self.assertEqual(sha1(b"12345" + b"secret").hexdigest(), str(handshake))`
  tp: rule py-hashlib-import: sha1 imported from hashlib
- **vault** `builtin/credential/cert/backend_test.go:1604:ECDSA`
  `caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/acme_challenges_test.go:529:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/acme_challenges_test.go:573:SHA-256`
  `checksum := sha256.Sum256([]byte("valid.valid"))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **vault** `builtin/logical/pki/export_crypto.go:272:ECDH`
  `ephPriv, err = ecdh.P384().GenerateKey(rand.Reader)`
  tp: rule go-package-call: ecdh.P384, crypto/ecdh imported, name not shadowed
- **vault** `builtin/logical/pki/export_crypto.go:354:AES`
  `block, err := aes.NewCipher(key)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **vault** `builtin/logical/pki/path_acme_test.go:1946:ECDSA`
  `csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/path_acme_test.go:251:ECDSA`
  `csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/path_acme_test.go:754:RSA-2048`
  `accountKey, err := rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **vault** `builtin/logical/pki/path_acme_test.go:932:ECDSA`
  `csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/path_secure_export_key_test.go:73:RSA`
  `cek, err := rsa.DecryptOAEP(sha256.New(), nil, priv, blob.WrappedCEK, nil)`
  tp: rule go-package-call: rsa.DecryptOAEP, crypto/rsa imported, name not shadowed
- **vault** `builtin/logical/pki/path_secure_export_key_test.go:73:SHA-256`
  `cek, err := rsa.DecryptOAEP(sha256.New(), nil, priv, blob.WrappedCEK, nil)`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **vault** `builtin/logical/transit/path_import.go:472:SHA-1`
  `return sha1.New(), nil`
  tp: rule go-package-call: sha1.New, crypto/sha1 imported, name not shadowed
- **vault** `command/server/operator_raft_snapshot_inspect.go:426:SHA-256`
  `h := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **vault** `helper/pkcs7/encrypt.go:193:3DES`
  `block, err = des.NewTripleDESCipher(key)`
  tp: rule go-package-call: des.NewTripleDESCipher, crypto/des imported, name not shadowed
- **vault** `helper/pkcs7/verify.go:159:DSA`
  `if !dsa.Verify(dsaKey, signed, dsaSig.R, dsaSig.S) {`
  tp: rule go-package-call: dsa.Verify, crypto/dsa imported, name not shadowed
- **vault** `helper/testhelpers/pki/pkihelper.go:183:ECDSA`
  `caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `physical/raft/raft_test.go:994:MD5`
  `pe.Key = fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s-%d", testName, i))))`
  tp: rule go-package-call: md5.Sum, crypto/md5 imported, name not shadowed
- **vault** `sdk/helper/certutil/cert_verification_test.go:231:ECDSA`
  `subIntKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `sdk/helper/certutil/cert_verification_test.go:343:ECDSA`
  `rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `sdk/helper/certutil/certutil_test.go:878:Ed25519`
  `pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)`
  tp: rule go-package-call: ed25519.GenerateKey, crypto/ed25519 imported, name not shadowed
- **vault** `sdk/helper/certutil/helpers.go:429:Ed25519`
  `_, privateKey, err = ed25519.GenerateKey(randReader)`
  tp: read by hand: call into the named algorithm confirmed in context
- **vault** `sdk/helper/keysutil/policy.go:1631:RSA`
  `err = rsa.VerifyPKCS1v15(publicKey, algo, input, sigBytes)`
  tp: rule go-package-call: rsa.VerifyPKCS1v15, crypto/rsa imported, name not shadowed
- **vault** `sdk/helper/keysutil/policy_test.go:881:ECDSA`
  `ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `sdk/helper/ocsp/ocsp_test.go:569:ECDSA`
  `leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `sdk/helper/salt/salt.go:190:SHA-1`
  `hashed := sha1.Sum(inp)`
  tp: rule go-package-call: sha1.Sum, crypto/sha1 imported, name not shadowed
- **vault** `sdk/helper/testcluster/blackbox/session_plugin.go:26:SHA-256`
  `hasher := sha256.New()`
  tp: read by hand: call into the named algorithm confirmed in context
- **vault** `sdk/helper/tpm/attestation.go:557:SHA-256`
  `appPubSum := sha256.Sum256(appPubDER)`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **vault** `vault/bench/smoke_bench_test.go:58:MD5`
  `key := fmt.Sprintf("%s/%x", secretPath, md5.Sum([]byte(fmt.Sprintf("%s-%d", testName, i))))`
  tp: rule go-package-call: md5.Sum, crypto/md5 imported, name not shadowed
- **vault** `vault/identity_store_oidc.go:1822:Ed25519`
  `_, key, err = ed25519.GenerateKey(rand.Reader)`
  tp: rule go-package-call: ed25519.GenerateKey, golang.org/x/crypto/ed25519 imported, name not shadowed
- **vault** `vault/testing.go:1350:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `vault/wrapping.go:41:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P521(), c.secureRandomReader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **x-crypto** `acme/autocert/autocert_test.go:830:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: read by hand: TLS certificate keys (signing)
- **x-crypto** `acme/autocert/internal/acmetest/ca.go:556:RSA-1024`
  `pk, err = rsa.GenerateKey(rand.Reader, 1024)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **x-crypto** `acme/pebble_test.go:473:ECDSA`
  `certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **x-crypto** `otr/otr.go:790:SHA-256`
  `h := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **x-crypto** `otr/smp.go:532:SHA-256`
  `h := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **x-crypto** `ssh/agent/client.go:618:EC`
  `KeyBytes:    elliptic.Marshal(k.Curve, k.X, k.Y),`
  tp: read by hand: EC, usage undetermined: SSH agent ECDSA key encoding (actual use: ECDSA)
- **x-crypto** `ssh/certs_test.go:222:ECDSA`
  `userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **x-crypto** `ssh/kex.go:232:EC`
  `ClientPubKey: elliptic.Marshal(kex.curve, ephKey.PublicKey.X, ephKey.PublicKey.Y),`
  tp: read by hand: EC, usage undetermined: SSH ECDH done with ecdsa.GenerateKey keys and ScalarMult (actual use: ECDH)
- **x-crypto** `ssh/kex.go:256:EC`
  `secret, _ := kex.curve.ScalarMult(x, y, ephKey.D.Bytes())`
  tp: read by hand: EC, usage undetermined: SSH ECDH done with ecdsa.GenerateKey keys and ScalarMult (actual use: ECDH)
- **x-crypto** `ssh/kex.go:337:EC`
  `ephKey, err := ecdsa.GenerateKey(kex.curve, rand)`
  tp: read by hand: EC, usage undetermined: SSH ECDH done with ecdsa.GenerateKey keys and ScalarMult (actual use: ECDH)
- **x-crypto** `ssh/kex.go:347:EC`
  `secret, _ := kex.curve.ScalarMult(clientX, clientY, ephKey.D.Bytes())`
  tp: read by hand: EC, usage undetermined: SSH ECDH done with ecdsa.GenerateKey keys and ScalarMult (actual use: ECDH)
- **x-crypto** `ssh/kex.go:551:X25519`
  `secret, err := curve25519.X25519(kp.priv[:], kexInit.ClientPubKey)`
  tp: rule go-package-call: curve25519.X25519-family call, golang.org/x/crypto/curve25519 imported, name not shadowed
- **x-crypto** `ssh/keys.go:604:RSA`
  `return rsa.VerifyPKCS1v15((*rsa.PublicKey)(r), hash, digest, blob)`
  tp: rule go-package-call: rsa.VerifyPKCS1v15, crypto/rsa imported, name not shadowed
- **x-crypto** `ssh/keys.go:835:Ed25519`
  `if ok := ed25519.Verify(ed25519.PublicKey(k), b, sig.Blob); !ok {`
  tp: rule go-package-call: ed25519.Verify, crypto/ed25519 imported, name not shadowed
- **x-crypto** `ssh/knownhosts/knownhosts_test.go:329:Ed25519`
  `_, hostPriv, err := ed25519.GenerateKey(rand.Reader)`
  tp: rule go-package-call: ed25519.GenerateKey, crypto/ed25519 imported, name not shadowed

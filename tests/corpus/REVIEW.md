# Label review sheet

Every false positive, and a random 10% of true positives (seed 20261014,
regenerated from the committed labels by `review.py`). Change a verdict in
`labels/<name>.json` and say why in the commit message.

## False positives (1)

- **go-jose** `asymmetric.go:395:ECDSA`
  `priv, err := ecdsa.GenerateKey(ctx.publicKey.Curve, randReader)`
  fp: read by hand: ecdsa.GenerateKey makes the ephemeral key for ECDH-ES in genKey(); the agreement is in cipher/ecdh_es.go. ECDSA usage label is wrong

## True positives, random sample (100 of 995)

- **age** `agessh/agessh.go:212:X25519`
  `ourPublicKey, err := curve25519.X25519(ephemeral, curve25519.Basepoint)`
  tp: rule go-package-call: curve25519.X25519-family call, golang.org/x/crypto/curve25519 imported, name not shadowed
- **age** `agessh/agessh.go:329:X25519`
  `sharedSecret, err := curve25519.X25519(i.secretKey, publicKey)`
  tp: rule go-package-call: curve25519.X25519-family call, golang.org/x/crypto/curve25519 imported, name not shadowed
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
- **cfssl** `scan/crypto/tls/key_agreement.go:374:RSA`
  `if err := rsa.VerifyPKCS1v15(pubKey, hashFunc, digest, sig); err != nil {`
  tp: rule go-package-call: rsa.VerifyPKCS1v15, crypto/rsa imported, name not shadowed
- **cfssl** `scan/crypto/tls/key_agreement.go:392:EC`
  `x, _ := ka.curve.ScalarMult(ka.x, ka.y, priv)`
  tp: read by hand: EC, usage undetermined: copy of Go's TLS ECDHE key agreement (actual use: ECDH)
- **cfssl** `transport/kp/key_provider.go:230:ECDSA`
  `priv, err = ecdsa.GenerateKey(curve, rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **go-jose** `asymmetric.go:249:RSA`
  `_ = rsa.DecryptPKCS1v15SessionKey(rand.Reader, ctx.privateKey, jek, cek)`
  tp: rule go-package-call: rsa.DecryptPKCS1v15SessionKey, crypto/rsa imported, name not shadowed
- **go-jose** `asymmetric.go:257:RSA`
  `return rsa.DecryptOAEP(sha256.New(), rand.Reader, ctx.privateKey, jek, []byte{})`
  tp: rule go-package-call: rsa.DecryptOAEP, crypto/rsa imported, name not shadowed
- **go-jose** `asymmetric_test.go:233:RSA-2048`
  `priv, err := rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **go-jose** `cryptosigner/cryptosigner_test.go:129:ECDSA`
  `key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **go-jose** `jwk_test.go:487:SHA-256`
  `x5tSHA256 := sha256.Sum256(testCertificates[0].Raw)`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **go-jose** `signing_test.go:446:ECDSA`
  `key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **go-jose** `signing_test.go:450:ECDSA`
  `key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **go-jose** `signing_test.go:524:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **go-jose** `symmetric.go:338:AES`
  `block, err := aes.NewCipher(key)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **paramiko** `paramiko/kex_ecdh_nist.py:71:ECDH`
  `K = self.P.exchange(ec.ECDH(), self.Q_C)`
  tp: read by hand: SSH ECDH key exchange
- **pyjwt** `tests/test_algorithms.py:1755:RSA-1024`
  `small_key = rsa_module.generate_private_key(`
  tp: read by hand: deliberately undersized RSA key in a test of key-size rejection
- **python-jose** `jose/backends/cryptography_backend.py:139:ECDSA`
  `signature = self.prepared_key.sign(msg, ec.ECDSA(self.hash_alg()))`
  tp: read by hand: call into the named algorithm confirmed in context
- **python-jose** `jose/backends/cryptography_backend.py:145:ECDSA`
  `self.prepared_key.verify(signature, msg, ec.ECDSA(self.hash_alg()))`
  tp: read by hand: call into the named algorithm confirmed in context
- **python-jose** `jose/backends/cryptography_backend.py:306:RSA`
  `signature = self.prepared_key.sign(msg, padding.PKCS1v15(), self.hash_alg())`
  tp: rule py-cryptography-object: padding.PKCS1v15(), padding imported once from cryptography.hazmat.primitives.asymmetric, bound nowhere else
- **scapy** `scapy/layers/msrpce/msnrpc.py:151:MD5`
  `digest = hashes.Hash(hashes.MD5())`
  tp: read by hand: hashes from cryptography.hazmat.primitives, rebound only to None when cryptography is missing
- **scapy** `scapy/layers/msrpce/msnrpc.py:248:MD5`
  `h = hmac.HMAC(h.finalize(), hashes.MD5())`
  tp: read by hand: hashes from cryptography.hazmat.primitives, rebound only to None when cryptography is missing; used in HMAC
- **scapy** `scapy/layers/tls/keyexchange.py:858:ECDH`
  `pms = s.client_kx_privkey.exchange(ec.ECDH(),`
  tp: read by hand: call into the named algorithm confirmed in context
- **scapy** `scapy/layers/tls/keyexchange_tls13.py:205:ECDH`
  `pms = privkey.exchange(ec.ECDH(), pubkey)`
  tp: read by hand: call into the named algorithm confirmed in context
- **scapy** `scapy/libs/rfc3961.py:926:SHA-1`
  `algorithm=hashes.SHA1(),`
  tp: rule py-cryptography-object: hashes.SHA1(), hashes imported once from cryptography.hazmat.primitives, bound nowhere else
- **scapy** `scapy/utils6.py:431:SHA-1`
  `globalid = hashlib.sha1(btod + eui64).digest()[:5]`
  tp: rule py-hashlib: hashlib.sha1() call
- **step-ca** `acme/challenge.go:1809:Ed25519`
  `if !ed25519.Verify(pub, []byte(keyAuth), sig) {`
  tp: rule go-package-call: ed25519.Verify, crypto/ed25519 imported, name not shadowed
- **step-ca** `acme/challenge.go:378:SHA-256`
  `h := sha256.Sum256([]byte(expectedKeyAuth))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `acme/challenge_test.go:2188:SHA-256`
  `h := sha256.Sum256([]byte(expKeyAuth))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `acme/challenge_test.go:3101:SHA-256`
  `incorrectTokenHash := sha256.Sum256([]byte("mismatched"))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `acme/challenge_tpmsimulator_test.go:62:SHA-256`
  `hash := sha256.Sum256(b)`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `api/ssh_test.go:39:ECDSA`
  `priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `authority/authority.go:507:SHA-256`
  `sum := sha256.Sum256(crt.Raw)`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `authority/authorize.go:213:SHA-256`
  `sum := sha256.Sum256([]byte(token))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `authority/provisioner/aws_test.go:62:SHA-256`
  `sum := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", p1.GetID(), claims.document.InstanceID)))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `authority/provisioner/aws_test.go:755:RSA-1024`
  `rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **step-ca** `authority/ssh_test.go:460:ECDSA`
  `key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `cas/stepcas/x5c_issuer_test.go:246:ECDSA`
  `p256 := mustSigner(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `cas/vaultcas/vaultcas.go:165:SHA-256`
  `sum := sha256.Sum256(cert.root.Raw)`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `test/integration/scep/common_test.go:305:RSA-2048`
  `signer, err = rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **twisted** `src/twisted/conch/scripts/ckeygen.py:168:EC`
  `keyPrimitive = ec.generate_private_key(curve=keys._curveTable[curve])`
  tp: read by hand: SSH key generation (EC actual use: ECDSA)
- **twisted** `src/twisted/conch/ssh/transport.py:2131:MD5`
  `[binascii.hexlify(c) for c in iterbytes(md5(pubKey).digest())]`
  tp: rule py-hashlib-import: md5 imported from hashlib
- **twisted** `src/twisted/conch/test/test_keys.py:1538:RSA`
  `common.getNS(signature)[0], data, padding.PKCS1v15(), hashes.SHA512()`
  tp: rule py-cryptography-object: padding.PKCS1v15(), padding imported once from cryptography.hazmat.primitives.asymmetric, bound nowhere else
- **twisted** `src/twisted/cred/test/test_digestauth.py:101:MD5`
  `ha1 = hexlify(md5(a1).digest())`
  tp: rule py-hashlib-import: md5 imported from hashlib
- **twisted** `src/twisted/mail/test/test_mail.py:1003:MD5`
  `resp = md5("wrong digest").hexdigest()`
  tp: rule py-hashlib-import: md5 imported from hashlib
- **twisted** `src/twisted/words/protocols/jabber/xmlstream.py:77:SHA-1`
  `return sha1(input.encode("utf-8")).hexdigest()`
  tp: rule py-hashlib-import: sha1 imported from hashlib
- **vault** `builtin/credential/cert/backend_test.go:95:ECDSA`
  `caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/acme_challenges_test.go:677:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/acme_challenges_test.go:717:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/backend_test.go:1341:ECDSA`
  `privKey, _ = ecdsa.GenerateKey(curve, rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/path_acme_test.go:456:ECDSA`
  `accountKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/path_secure_export_key_test.go:117:AES`
  `block, err := aes.NewCipher(key)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **vault** `builtin/logical/transit/path_import_test.go:1135:Ed25519`
  `_, priv, err := ed25519.GenerateKey(rand.Reader)`
  tp: read by hand: call into the named algorithm confirmed in context
- **vault** `command/server/server.go:2213:SHA-256`
  `hasher := sha256.New()`
  tp: read by hand: call into the named algorithm confirmed in context
- **vault** `helper/pkcs7/decrypt.go:197:DES`
  `block, err = des.NewCipher(key)`
  tp: rule go-package-call: des.NewCipher, crypto/des imported, name not shadowed
- **vault** `helper/pkcs7/encrypt.go:115:AES`
  `block, err := aes.NewCipher(key)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **vault** `helper/storagepacker/storagepacker.go:119:MD5`
  `hf := md5.New()`
  tp: rule go-package-call: md5.New, crypto/md5 imported, name not shadowed
- **vault** `internalshared/dhutil/dhutil.go:150:AES`
  `block, err := aes.NewCipher(key)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **vault** `internalshared/listenerutil/tls_reload.go:53:SHA-256`
  `key:   sha256.Sum256(keyPEM),`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **vault** `sdk/helper/certutil/certutil_test.go:1367:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `sdk/helper/certutil/certutil_test.go:706:ECDSA`
  `intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `sdk/helper/certutil/types_test.go:29:Ed25519`
  `publicKey, _, err := ed25519.GenerateKey(rand.Reader)`
  tp: read by hand: call into the named algorithm confirmed in context
- **vault** `sdk/helper/keysutil/policy.go:1400:RSA`
  `sig, err = rsa.SignPSS(rand.Reader, key, algo, input, &rsa.PSSOptions{SaltLength: saltLength})`
  tp: rule go-package-call: rsa.SignPSS, crypto/rsa imported, name not shadowed
- **vault** `sdk/helper/keysutil/policy.go:2822:RSA`
  `ephKeyWrapped, err := rsa.EncryptOAEP(hash, rand.Reader, wrappingKey, ephKey, []byte{} /* label */)`
  tp: rule go-package-call: rsa.EncryptOAEP, crypto/rsa imported, name not shadowed
- **vault** `sdk/helper/keysutil/policy_test.go:938:Ed25519`
  `_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)`
  tp: rule go-package-call: ed25519.GenerateKey, golang.org/x/crypto/ed25519 imported, name not shadowed
- **vault** `sdk/helper/salt/salt.go:196:SHA-256`
  `hashed := sha256.Sum256(inp)`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **vault** `sdk/logical/token_test.go:62:SHA-256`
  `hashed := sha256.Sum256([]byte(expectedIDPlaintext))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **vault** `tools/pipeline/internal/pkg/golang/check_generate.go:255:SHA-256`
  `h := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **vault** `vault/external_tests/exactdeny/case_insensitive_bypass_test.go:97:RSA-2048`
  `key, err := rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **vault** `vault/plugincatalog/testing.go:72:SHA-256`
  `hash := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **x-crypto** `acme/acme.go:616:SHA-256`
  `shasum := sha256.Sum256([]byte(ka))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **x-crypto** `acme/autocert/autocert.go:636:RSA-2048`
  `key, err = rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **x-crypto** `acme/autocert/autocert_test.go:636:ECDSA`
  `ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: read by hand: TLS certificate keys (signing)
- **x-crypto** `acme/autocert/autocert_test.go:830:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: read by hand: TLS certificate keys (signing)
- **x-crypto** `acme/jws_test.go:271:SHA-256`
  `h := sha256.Sum256([]byte(protected + "." + payload))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **x-crypto** `ed25519/ed25519_test.go:15:Ed25519`
  `public, private, _ := ed25519std.GenerateKey(nil)`
  tp: read by hand: ed25519std is crypto/ed25519 imported under an alias; GenerateKey makes an Ed25519 key
- **x-crypto** `otr/otr.go:1232:DSA`
  `ok := dsa.Verify(&pk.PublicKey, hashed, r, s)`
  tp: rule go-package-call: dsa.Verify, crypto/dsa imported, name not shadowed
- **x-crypto** `otr/otr.go:1278:DSA`
  `if err := dsa.GenerateKey(&priv.PrivateKey, rand); err != nil {`
  tp: rule go-package-call: dsa.GenerateKey, crypto/dsa imported, name not shadowed
- **x-crypto** `otr/otr.go:732:AES`
  `aesCipher, err := aes.NewCipher(keys.c[:])`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **x-crypto** `otr/otr.go:790:SHA-256`
  `h := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **x-crypto** `ssh/certs_test.go:507:ECDSA`
  `k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **x-crypto** `ssh/cipher.go:57:RC4`
  `return rc4.NewCipher(key)`
  tp: rule go-package-call: rc4.NewCipher, crypto/rc4 imported, name not shadowed
- **x-crypto** `ssh/example_test.go:479:RSA-3072`
  `privateKey, err := rsa.GenerateKey(rand.Reader, 3072)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **x-crypto** `ssh/keys.go:835:Ed25519`
  `if ok := ed25519.Verify(ed25519.PublicKey(k), b, sig.Blob); !ok {`
  tp: rule go-package-call: ed25519.Verify, crypto/ed25519 imported, name not shadowed
- **x-crypto** `ssh/keys_test.go:76:ECDSA`
  `raw, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **x-crypto** `ssh/mlkem.go:129:SHA-256`
  `h := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **x-crypto** `x509roots/gen_fallback_bundle.go:120:SHA-256`
  `sha256.Sum256(c.X509.Raw),`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed

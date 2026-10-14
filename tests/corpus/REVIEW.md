# Label review sheet

Every false positive, and a random 10% of true positives (seed 20261014,
regenerated from the committed labels). Change a verdict in `labels/<name>.json`
and say why in the commit message.

## False positives (9)

- **go-jose** `asymmetric.go:395:ECDSA`
  `priv, err := ecdsa.GenerateKey(ctx.publicKey.Curve, randReader)`
  fp: read by hand: ecdsa.GenerateKey makes the ephemeral key for ECDH-ES in genKey(); the agreement is in cipher/ecdh_es.go. ECDSA usage label is wrong
- **go-jose** `crypter_test.go:39:ECDSA`
  `var ecTestKey256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  fp: read by hand: shared test key used for ECDH-ES encryption in crypter tests (and JWK round-trips); ECDSA usage label is wrong
- **go-jose** `crypter_test.go:40:ECDSA`
  `var ecTestKey384, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)`
  fp: read by hand: shared test key used for ECDH-ES encryption in crypter tests; ECDSA usage label is wrong
- **go-jose** `crypter_test.go:41:ECDSA`
  `var ecTestKey521, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)`
  fp: read by hand: shared test key used for ECDH-ES encryption in crypter tests; ECDSA usage label is wrong
- **go-jose** `jose-util/generator/generate.go:113:ECDSA`
  `key, err := ecdsa.GenerateKey(crv, rand.Reader)`
  fp: read by hand: key generated for the ECDH_ES* algorithms; ECDSA usage label is wrong
- **vault** `builtin/logical/pki/export_crypto.go:96:ECDSA`
  `k, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  fp: read by hand: EC key generated for export with no visible use; ECDSA claims signing without evidence (EC, usage undetermined, would be right). Judgement call
- **vault** `builtin/logical/pki/export_crypto.go:102:ECDSA`
  `k, genErr := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)`
  fp: read by hand: as line 96: export key with no visible use; ECDSA claims signing without evidence. Judgement call
- **vault** `builtin/logical/pki/export_crypto.go:108:ECDSA`
  `k, genErr := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)`
  fp: read by hand: as line 96: export key with no visible use; ECDSA claims signing without evidence. Judgement call
- **vault** `builtin/logical/pki/path_secure_export_key_test.go:48:ECDSA`
  `priv, err := ecdsa.GenerateKey(curve, rand.Reader)`
  fp: read by hand: generateECWrapKey: recipient key for ECDH-ES wrapping; ECDSA usage label is wrong

## True positives, random sample (93 of 927)

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
- **caddy** `caddytest/integration/ech_test.go:107:X25519`
  `key, err := ecdh.X25519().GenerateKey(rand.Reader)`
  tp: rule go-package-call: ecdh.X25519-family call, crypto/ecdh imported, name not shadowed
- **caddy** `modules/caddyhttp/replacer.go:573:SHA-256`
  `return fmt.Sprintf("%x", sha256.Sum256(cert.Raw)), true`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **certbot** `certbot-ci/src/certbot_integration_tests/utils/misc.py:220:EC-SECP384R1`
  `key = ec.generate_private_key(ec.SECP384R1())`
  tp: read by hand: EC keys sign certificates or CSRs (actual use: ECDSA); RSA keys are account and certificate keys
- **cfssl** `api/generator/generator.go:101:SHA-1`
  `sha1Sum := sha1.Sum(data)`
  tp: rule go-package-call: sha1.Sum, crypto/sha1 imported, name not shadowed
- **cfssl** `bundler/bundle_from_remote_test.go:236:ECDSA`
  `leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **cfssl** `helpers/derhelpers/ed25519.go:131:Ed25519`
  `return ed25519.NewKeyFromSeed(*seed), nil`
  tp: rule go-package-call: ed25519.NewKeyFromSeed, crypto/ed25519 imported, name not shadowed
- **cfssl** `scan/crypto/rsa/pkcs1v15_test.go:215:SHA-1`
  `h := sha1.New()`
  tp: rule go-package-call: sha1.New, crypto/sha1 imported, name not shadowed
- **cfssl** `scan/crypto/tls/cipher_suites.go:103:3DES`
  `block, _ := des.NewTripleDESCipher(key)`
  tp: rule go-package-call: des.NewTripleDESCipher, crypto/des imported, name not shadowed
- **cfssl** `scan/crypto/tls/key_agreement.go:101:MD5`
  `hmd5 := md5.New()`
  tp: rule go-package-call: md5.New, crypto/md5 imported, name not shadowed
- **cfssl** `scan/crypto/tls/key_agreement.go:392:EC`
  `x, _ := ka.curve.ScalarMult(ka.x, ka.y, priv)`
  tp: read by hand: EC, usage undetermined: copy of Go's TLS ECDHE key agreement (actual use: ECDH)
- **cfssl** `scan/crypto/tls/key_agreement.go:76:RSA`
  `encrypted, err := rsa.EncryptPKCS1v15(config.rand(), cert.PublicKey.(*rsa.PublicKey), preMasterSecret)`
  tp: rule go-package-call: rsa.EncryptPKCS1v15, crypto/rsa imported, name not shadowed
- **cfssl** `scan/crypto/tls/prf.go:267:MD5`
  `md5Digest = md5.Sum(nil)`
  tp: rule go-package-call: md5.Sum, crypto/md5 imported, name not shadowed
- **cfssl** `scan/crypto/tls/prf.go:278:SHA-1`
  `sha1Digest = sha1.Sum(nil)`
  tp: read by hand: SSL 3.0 / TLS 1.0 PRF and finished hash; some calls are on a local variable named sha1 holding a SHA-1 hash
- **django** `django/db/backends/sqlite3/_functions.py:460:SHA-1`
  `return sha1(text.encode()).hexdigest()`
  tp: rule py-hashlib-import: sha1 imported from hashlib
- **go-jose** `asymmetric.go:372:AES`
  `block, err := aes.NewCipher(kek)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **go-jose** `asymmetric.go:537:ECDSA`
  `r, s, err := ecdsa.Sign(randReader, ctx.privateKey, hashed)`
  tp: rule go-package-call: ecdsa.Sign, crypto/ecdsa imported, name not shadowed
- **go-jose** `cipher/key_wrap_test.go:85:AES`
  `block1, _ := aes.NewCipher(kek1)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **go-jose** `jose-util/generator/generate.go:67:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)`
  tp: read by hand: ES256/384/512 signing keys
- **go-jose** `symmetric.go:300:AES`
  `block, err := aes.NewCipher(ctx.key)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **golang-jwt** `ed25519.go:49:Ed25519`
  `if !ed25519.Verify(ed25519Key, []byte(signingString), sig) {`
  tp: rule go-package-call: ed25519.Verify, crypto/ed25519 imported, name not shadowed
- **golang-jwt** `rsa.go:65:RSA`
  `return rsa.VerifyPKCS1v15(rsaKey, m.Hash, hasher.Sum(nil), sig)`
  tp: rule go-package-call: rsa.VerifyPKCS1v15, crypto/rsa imported, name not shadowed
- **golang-jwt** `rsa_pss.go:103:RSA`
  `return rsa.VerifyPSS(rsaKey, m.Hash, hasher.Sum(nil), sig, opts)`
  tp: rule go-package-call: rsa.VerifyPSS, crypto/rsa imported, name not shadowed
- **paramiko** `paramiko/ecdsakey.py:242:ECDSA`
  `signature, data, ec.ECDSA(self.ecdsa_curve.hash_object())`
  tp: read by hand: SSH ECDSA host and user keys
- **python-jose** `jose/backends/cryptography_backend.py:145:ECDSA`
  `self.prepared_key.verify(signature, msg, ec.ECDSA(self.hash_alg()))`
  tp: read by hand: call into the named algorithm confirmed in context
- **scapy** `scapy/layers/tls/cert.py:899:ECDSA`
  `self.key = ec.generate_private_key(curve(), default_backend())`
  tp: read by hand: call into the named algorithm confirmed in context
- **scapy** `scapy/layers/tls/keyexchange.py:887:ECDH`
  `ZZ = s.server_kx_privkey.exchange(ec.ECDH(), s.client_kx_pubkey)`
  tp: read by hand: call into the named algorithm confirmed in context
- **scapy** `scapy/layers/tls/keyexchange_tls13.py:181:ECDH`
  `pms = privkey.exchange(ec.ECDH(), pubkey)`
  tp: read by hand: call into the named algorithm confirmed in context
- **scapy** `scapy/utils6.py:431:SHA-1`
  `globalid = hashlib.sha1(btod + eui64).digest()[:5]`
  tp: rule py-hashlib: hashlib.sha1() call
- **step-ca** `acme/challenge.go:1805:RSA`
  `if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {`
  tp: rule go-package-call: rsa.VerifyPKCS1v15, crypto/rsa imported, name not shadowed
- **step-ca** `acme/challenge_test.go:206:SHA-256`
  `nonceSum := sha256.Sum256([]byte(nonce))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `acme/challenge_test.go:3148:SHA-256`
  `incorrectTokenHash := sha256.Sum256([]byte("mismatched"))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `acme/challenge_test.go:3286:SHA-256`
  `expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `acme/challenge_test.go:3698:ECDSA`
  `otherSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `acme/challenge_test.go:5110:ECDSA`
  `signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `acme/challenge_tpmsimulator_test.go:492:SHA-256`
  `keyAuthSum := sha256.Sum256([]byte(keyAuthorization))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `api/api_test.go:1485:DSA`
  `if err := dsa.GenerateKey(&dsa2048, rand.Reader); err != nil {`
  tp: rule go-package-call: dsa.GenerateKey, crypto/dsa imported, name not shadowed
- **step-ca** `authority/provisioner/aws.go:266:SHA-256`
  `sum := sha256.Sum256([]byte(unique))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `authority/provisioner/collection.go:325:SHA-1`
  `sum := sha1.Sum([]byte(p.GetID()))`
  tp: rule go-package-call: sha1.Sum, crypto/sha1 imported, name not shadowed
- **step-ca** `authority/provisioner/utils_test.go:562:SHA-256`
  `sum := sha256.Sum256(doc)`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `authority/ssh_test.go:460:ECDSA`
  `key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `authority/ssh_test.go:505:ECDSA`
  `key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `authority/ssh_test.go:887:ECDSA`
  `signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `ca/client.go:1461:ECDSA`
  `pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `cas/cloudcas/cloudcas_test.go:228:Ed25519`
  `pub, _, err := ed25519.GenerateKey(rand.Reader)`
  tp: rule go-package-call: ed25519.GenerateKey, crypto/ed25519 imported, name not shadowed
- **twisted** `src/twisted/conch/ssh/transport.py:1361:ECDH`
  `return ec.generate_private_key(curve)`
  tp: read by hand: call into the named algorithm confirmed in context
- **twisted** `src/twisted/conch/test/test_transport.py:2481:SHA-1`
  `h = sha1()`
  tp: rule py-hashlib-import: sha1 imported from hashlib
- **twisted** `src/twisted/internet/test/test_unix.py:100:MD5`
  `return md5(urandom(100)).hexdigest()`
  tp: rule py-hashlib-import: md5 imported from hashlib
- **twisted** `src/twisted/mail/pop3.py:1603:MD5`
  `digest = md5(magic + password).hexdigest().encode("ascii")`
  tp: rule py-hashlib-import: md5 imported from hashlib
- **twisted** `src/twisted/test/test_sslverify.py:3526:EC-SECP256R1`
  `key = ec.generate_private_key(ec.SECP256R1())`
  tp: read by hand: EC, usage undetermined: signs a CSR (actual use: ECDSA)
- **twisted** `src/twisted/words/test/test_jabbercomponent.py:88:SHA-1`
  `hv = sha1(b"12345" + b"secret").hexdigest().encode("ascii")`
  tp: rule py-hashlib-import: sha1 imported from hashlib
- **vault** `builtin/credential/cert/backend_test.go:1913:ECDSA`
  `caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/credential/cert/path_crls_test.go:99:ECDSA`
  `clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/acme_challenges_test.go:453:ECDSA`
  `rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/backend_test.go:846:ECDSA`
  `priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/export_crypto.go:270:ECDH`
  `ephPriv, err = ecdh.P256().GenerateKey(rand.Reader)`
  tp: rule go-package-call: ecdh.P256, crypto/ecdh imported, name not shadowed
- **vault** `builtin/logical/pki/export_crypto_test.go:68:ECDSA`
  `caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/transit/path_import_test.go:1104:RSA`
  `ephKeyWrapped, err := rsa.EncryptOAEP(hashFn, rand.Reader, wrappingKey, ephKey, []byte{})`
  tp: rule go-package-call: rsa.EncryptOAEP, crypto/rsa imported, name not shadowed
- **vault** `builtin/logical/transit/path_import_test.go:1135:Ed25519`
  `_, priv, err := ed25519.GenerateKey(rand.Reader)`
  tp: read by hand: call into the named algorithm confirmed in context
- **vault** `command/server/operator_raft_snapshot_inspect.go:426:SHA-256`
  `h := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **vault** `internalshared/dhutil/dhutil.go:56:X25519`
  `return curve25519.X25519(ourPrivate, theirPublic)`
  tp: rule go-package-call: curve25519.X25519-family call, golang.org/x/crypto/curve25519 imported, name not shadowed
- **vault** `sdk/helper/certutil/cert_verification_test.go:159:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `sdk/helper/certutil/certutil_test.go:671:ECDSA`
  `caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `sdk/helper/certutil/helpers.go:202:SHA-1`
  `skid := sha1.Sum(publicKeyBytes)`
  tp: rule go-package-call: sha1.Sum, crypto/sha1 imported, name not shadowed
- **vault** `sdk/helper/certutil/types_test.go:24:ECDSA`
  `ecdsaKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)`
  tp: read by hand: call into the named algorithm confirmed in context
- **vault** `sdk/helper/cryptoutil/rsa.go:31:RSA`
  `return rsa.GenerateKey(randomSource, bits)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **vault** `sdk/helper/keysutil/policy.go:2259:AES`
  `aesCipher, err := aes.NewCipher(encKey)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **vault** `sdk/helper/ocsp/ocsp_test.go:569:ECDSA`
  `leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `sdk/helper/pluginutil/tls.go:24:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `vault/cert_count/cert_count_manager_test.go:26:RSA-2048`
  `privateKey, err := rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **vault** `vault/external_tests/raft/raft_test.go:1307:MD5`
  `key := fmt.Sprintf("secret/%x", md5.Sum([]byte(fmt.Sprintf("%s-%d", testName, i))))`
  tp: rule go-package-call: md5.Sum, crypto/md5 imported, name not shadowed
- **vault** `vault/plugincatalog/plugin_artifact.go:543:SHA-256`
  `hasher := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **x-crypto** `acme/acme.go:616:SHA-256`
  `shasum := sha256.Sum256([]byte(ka))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **x-crypto** `acme/autocert/autocert_test.go:121:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: read by hand: TLS certificate keys (signing)
- **x-crypto** `acme/jws.go:252:SHA-256`
  `b := sha256.Sum256([]byte(jwk))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **x-crypto** `acme/jws_test.go:272:ECDSA`
  `if !ecdsa.Verify(testKeyEC.Public().(*ecdsa.PublicKey), h[:], r, s) {`
  tp: rule go-package-call: ecdsa.Verify, crypto/ecdsa imported, name not shadowed
- **x-crypto** `curve25519/curve25519_test.go:56:X25519`
  `out, err := curve25519.X25519(scalar[:], point[:])`
  tp: rule go-package-call: curve25519.X25519-family call, golang.org/x/crypto/curve25519 imported, name not shadowed
- **x-crypto** `ed25519/ed25519_test.go:19:Ed25519`
  `if !ed25519.Verify(public, message, sig) {`
  tp: rule go-package-call: ed25519.Verify, golang.org/x/crypto/ed25519 imported, name not shadowed
- **x-crypto** `nacl/box/box_test.go:59:X25519`
  `curve25519.ScalarBaseMult(&publicKey1, &privateKey1)`
  tp: rule go-package-call: curve25519.X25519-family call, golang.org/x/crypto/curve25519 imported, name not shadowed
- **x-crypto** `otr/otr.go:1242:DSA`
  `r, s, err := dsa.Sign(rand, &priv.PrivateKey, hashed)`
  tp: rule go-package-call: dsa.Sign, crypto/dsa imported, name not shadowed
- **x-crypto** `otr/otr.go:687:AES`
  `aesCipher, err := aes.NewCipher(keys.c[:])`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **x-crypto** `otr/smp.go:227:SHA-256`
  `h := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **x-crypto** `otr/smp.go:457:SHA-256`
  `h := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **x-crypto** `pkcs12/pbkdf.go:19:SHA-1`
  `sum := sha1.Sum(in)`
  tp: rule go-package-call: sha1.Sum, crypto/sha1 imported, name not shadowed
- **x-crypto** `ssh/cipher.go:313:AES`
  `c, err := aes.NewCipher(key)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **x-crypto** `ssh/cipher.go:491:3DES`
  `c, err := des.NewTripleDESCipher(key)`
  tp: rule go-package-call: des.NewTripleDESCipher, crypto/des imported, name not shadowed
- **x-crypto** `ssh/kex.go:226:EC`
  `ephKey, err := ecdsa.GenerateKey(kex.curve, rand)`
  tp: read by hand: EC, usage undetermined: SSH ECDH done with ecdsa.GenerateKey keys and ScalarMult (actual use: ECDH)
- **x-crypto** `ssh/mlkem.go:129:SHA-256`
  `h := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **x-crypto** `x509roots/gen_fallback_bundle.go:120:SHA-256`
  `sha256.Sum256(c.X509.Raw),`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed

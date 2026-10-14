# Label review sheet

Every false positive, and a random 10% of true positives (seed 20261014,
regenerated from the committed labels). Change a verdict in `labels/<name>.json`
and say why in the commit message.

## False positives (1)

- **go-jose** `asymmetric.go:395:ECDSA`
  `priv, err := ecdsa.GenerateKey(ctx.publicKey.Curve, randReader)`
  fp: read by hand: ecdsa.GenerateKey makes the ephemeral key for ECDH-ES in genKey(); the agreement is in cipher/ecdh_es.go. ECDSA usage label is wrong

## True positives, random sample (94 of 935)

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
- **go-jose** `doc_test.go:79:RSA-2048`
  `privateKey, err := rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **go-jose** `signing_test.go:524:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **go-jose** `symmetric.go:409:AES`
  `block, err := aes.NewCipher(ctx.key)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **go-jose** `symmetric.go:453:AES`
  `block, err := aes.NewCipher(key)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **golang-jwt** `ecdsa.go:111:ECDSA`
  `if r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hasher.Sum(nil)); err == nil {`
  tp: rule go-package-call: ecdsa.Sign, crypto/ecdsa imported, name not shadowed
- **golang-jwt** `rsa_pss.go:127:RSA`
  `if sigBytes, err := rsa.SignPSS(rand.Reader, rsaKey, m.Hash, hasher.Sum(nil), m.Options); err == nil {`
  tp: rule go-package-call: rsa.SignPSS, crypto/rsa imported, name not shadowed
- **pyjwt** `tests/test_algorithms.py:1769:RSA-1024`
  `small_key = rsa_module.generate_private_key(`
  tp: read by hand: deliberately undersized RSA key in a test of key-size rejection
- **scapy** `scapy/layers/tls/cert.py:463:RSA`
  `private_key = rsa.generate_private_key(`
  tp: read by hand: call into the named algorithm confirmed in context
- **scapy** `scapy/layers/tls/cert.py:899:ECDSA`
  `self.key = ec.generate_private_key(curve(), default_backend())`
  tp: read by hand: call into the named algorithm confirmed in context
- **scapy** `scapy/layers/tls/cert.py:917:ECDSA`
  `return self.key.sign(data, ec.ECDSA(_get_hash(h)))`
  tp: read by hand: call into the named algorithm confirmed in context
- **scapy** `scapy/layers/tls/keyexchange_tls13.py:205:ECDH`
  `pms = privkey.exchange(ec.ECDH(), pubkey)`
  tp: read by hand: call into the named algorithm confirmed in context
- **step-ca** `acme/challenge.go:1176:SHA-256`
  `hashedKeyAuth := sha256.Sum256([]byte(keyAuth))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `acme/challenge.go:1809:Ed25519`
  `if !ed25519.Verify(pub, []byte(keyAuth), sig) {`
  tp: rule go-package-call: ed25519.Verify, crypto/ed25519 imported, name not shadowed
- **step-ca** `acme/challenge_test.go:2974:SHA-256`
  `expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `acme/challenge_test.go:3147:SHA-256`
  `expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `acme/challenge_test.go:3324:SHA-256`
  `expKeyAuthHash := sha256.Sum256([]byte(expKeyAuth))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `acme/challenge_test.go:4678:ECDSA`
  `signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `acme/challenge_test.go:5195:ECDSA`
  `signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `api/api_test.go:1469:ECDSA`
  `p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `authority/authorize_test.go:1443:Ed25519`
  `_, otherSigner, err := ed25519.GenerateKey(rand.Reader)`
  tp: rule go-package-call: ed25519.GenerateKey, crypto/ed25519 imported, name not shadowed
- **step-ca** `authority/provisioner/azure.go:165:SHA-256`
  `sum := sha256.Sum256([]byte(claims.XMSMirID))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **step-ca** `authority/provisioner/scep_test.go:522:RSA-2048`
  `key, err := rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **step-ca** `authority/ssh_test.go:325:ECDSA`
  `signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `authority/ssh_test.go:418:ECDSA`
  `key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `authority/ssh_test.go:460:ECDSA`
  `key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **step-ca** `authority/tls_test.go:132:ECDSA`
  `priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: read by hand: call into the named algorithm confirmed in context
- **step-ca** `ca/client_test.go:113:ECDSA`
  `priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **twisted** `src/twisted/conch/ssh/keys.py:1033:MD5`
  `[binascii.hexlify(x) for x in iterbytes(md5(self.blob()).digest())]`
  tp: rule py-hashlib-import: md5 imported from hashlib
- **twisted** `src/twisted/conch/test/sk_dummy.py:90:ECDSA-SECP256R1`
  `ec_private_key = ec.generate_private_key(ec.SECP256R1())`
  tp: read by hand: call into the named algorithm confirmed in context
- **twisted** `src/twisted/cred/test/test_digestauth.py:505:MD5`
  `hash = md5(cleartext)`
  tp: rule py-hashlib-import: md5 imported from hashlib
- **twisted** `src/twisted/mail/_pop3client.py:884:MD5`
  `digest = md5(challenge + password).hexdigest().encode("ascii")`
  tp: rule py-hashlib-import: md5 imported from hashlib
- **twisted** `src/twisted/spread/pb.py:1263:MD5`
  `m = md5()`
  tp: rule py-hashlib-import: md5 imported from hashlib
- **twisted** `src/twisted/words/protocols/jabber/sasl_mechanisms.py:307:MD5`
  `return md5(nonceBytes).hexdigest().encode("ascii")`
  tp: rule py-hashlib-import: md5 imported from hashlib
- **vault** `builtin/credential/cert/backend_test.go:1392:ECDSA`
  `caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/credential/cert/backend_test.go:3816:ECDSA`
  `rootCaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/acme_challenges.go:83:SHA-256`
  `expectedAuthz := sha256.Sum256([]byte(authzContents))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **vault** `builtin/logical/pki/acme_challenges_test.go:677:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/pki/ca_util_test.go:25:ECDSA`
  `ecdsaKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)`
  tp: read by hand: call into the named algorithm confirmed in context
- **vault** `builtin/logical/pki/export_crypto.go:272:ECDH`
  `ephPriv, err = ecdh.P384().GenerateKey(rand.Reader)`
  tp: rule go-package-call: ecdh.P384, crypto/ecdh imported, name not shadowed
- **vault** `builtin/logical/pkiext/pkiext_binary/acme_test.go:1097:ECDSA`
  `csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/ssh/path_config_ca.go:408:ECDSA`
  `privateSeed, err := ecdsa.GenerateKey(curve, randomSource)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `builtin/logical/transit/path_import_test.go:1104:RSA`
  `ephKeyWrapped, err := rsa.EncryptOAEP(hashFn, rand.Reader, wrappingKey, ephKey, []byte{})`
  tp: rule go-package-call: rsa.EncryptOAEP, crypto/rsa imported, name not shadowed
- **vault** `helper/storagepacker/storagepacker.go:119:MD5`
  `hf := md5.New()`
  tp: rule go-package-call: md5.New, crypto/md5 imported, name not shadowed
- **vault** `physical/raft/raft_test.go:1027:MD5`
  `pe.Key = fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s-%d", testName, i))))`
  tp: rule go-package-call: md5.Sum, crypto/md5 imported, name not shadowed
- **vault** `sdk/helper/certutil/cert_verification_test.go:305:ECDSA`
  `leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `sdk/helper/certutil/certutil_test.go:1159:ECDSA`
  `caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `sdk/helper/certutil/certutil_test.go:1375:Ed25519`
  `key, priv, err := ed25519.GenerateKey(rand.Reader)`
  tp: rule go-package-call: ed25519.GenerateKey, crypto/ed25519 imported, name not shadowed
- **vault** `sdk/helper/certutil/certutil_test.go:706:ECDSA`
  `intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `sdk/helper/keysutil/policy.go:1400:RSA`
  `sig, err = rsa.SignPSS(rand.Reader, key, algo, input, &rsa.PSSOptions{SaltLength: saltLength})`
  tp: rule go-package-call: rsa.SignPSS, crypto/rsa imported, name not shadowed
- **vault** `sdk/helper/keysutil/policy.go:2395:RSA`
  `ciphertext, err = rsa.EncryptOAEP(hashFn(), rand.Reader, publicKey, plaintext, nil)`
  tp: rule go-package-call: rsa.EncryptOAEP, crypto/rsa imported, name not shadowed
- **vault** `sdk/helper/keysutil/policy.go:3063:ECDSA`
  `privKey, err := ecdsa.GenerateKey(curve, rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **vault** `sdk/logical/token.go:210:SHA-256`
  `hashed := sha256.Sum256([]byte(clientIDInput))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **vault** `vault/cert_count/cert_count_manager_test.go:26:RSA-2048`
  `privateKey, err := rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **vault** `vault/external_tests/exactdeny/case_insensitive_bypass_test.go:97:RSA-2048`
  `key, err := rsa.GenerateKey(rand.Reader, 2048)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **vault** `vault/logical_system.go:5482:SHA-256`
  `hf = sha256.New()`
  tp: read by hand: call into the named algorithm confirmed in context
- **vault** `vault/wrapping.go:41:ECDSA`
  `key, err := ecdsa.GenerateKey(elliptic.P521(), c.secureRandomReader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **x-crypto** `acme/autocert/autocert_test.go:720:ECDSA`
  `key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: read by hand: TLS certificate keys (signing)
- **x-crypto** `acme/autocert/internal/acmetest/ca.go:556:RSA-1024`
  `pk, err = rsa.GenerateKey(rand.Reader, 1024)`
  tp: rule go-package-call: rsa.GenerateKey, crypto/rsa imported, name not shadowed
- **x-crypto** `acme/jws_test.go:271:SHA-256`
  `h := sha256.Sum256([]byte(protected + "." + payload))`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed
- **x-crypto** `curve25519/curve25519_test.go:113:X25519`
  `out, err := curve25519.X25519(scalar, curve25519.Basepoint)`
  tp: rule go-package-call: curve25519.X25519-family call, golang.org/x/crypto/curve25519 imported, name not shadowed
- **x-crypto** `ed25519/ed25519.go:51:Ed25519`
  `return ed25519.GenerateKey(rand)`
  tp: rule go-package-call: ed25519.GenerateKey, crypto/ed25519 imported, name not shadowed
- **x-crypto** `nacl/box/box_test.go:150:X25519`
  `curve25519.ScalarBaseMult(&publicKey, &privateKey)`
  tp: rule go-package-call: curve25519.X25519-family call, golang.org/x/crypto/curve25519 imported, name not shadowed
- **x-crypto** `otr/otr.go:1242:DSA`
  `r, s, err := dsa.Sign(rand, &priv.PrivateKey, hashed)`
  tp: rule go-package-call: dsa.Sign, crypto/dsa imported, name not shadowed
- **x-crypto** `otr/otr.go:783:AES`
  `aesCipher, err := aes.NewCipher(r)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **x-crypto** `otr/smp.go:182:SHA-256`
  `h := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **x-crypto** `ssh/certs_test.go:222:ECDSA`
  `userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`
  tp: rule go-package-call: ecdsa.GenerateKey, crypto/ecdsa imported, name not shadowed; no key-agreement use in the file
- **x-crypto** `ssh/cipher.go:477:AES`
  `c, err := aes.NewCipher(key)`
  tp: rule go-package-call: aes.NewCipher, crypto/aes imported, name not shadowed
- **x-crypto** `ssh/cipher.go:57:RC4`
  `return rc4.NewCipher(key)`
  tp: rule go-package-call: rc4.NewCipher, crypto/rc4 imported, name not shadowed
- **x-crypto** `ssh/kex.go:226:EC`
  `ephKey, err := ecdsa.GenerateKey(kex.curve, rand)`
  tp: read by hand: EC, usage undetermined: SSH ECDH done with ecdsa.GenerateKey keys and ScalarMult (actual use: ECDH)
- **x-crypto** `ssh/keys.go:1776:EC`
  `X, Y := elliptic.Unmarshal(curve, key.Pub)`
  tp: read by hand: EC, usage undetermined: encodes or checks SSH ECDSA keys (actual use: ECDSA)
- **x-crypto** `ssh/mlkem.go:129:SHA-256`
  `h := sha256.New()`
  tp: rule go-package-call: sha256.New, crypto/sha256 imported, name not shadowed
- **x-crypto** `x509roots/gen_fallback_bundle.go:120:SHA-256`
  `sha256.Sum256(c.X509.Raw),`
  tp: rule go-package-call: sha256.Sum256, crypto/sha256 imported, name not shadowed

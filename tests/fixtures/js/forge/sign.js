var forge = require('node-forge');

function legacy(key, bits) {
  var md5 = forge.md.md5.create();
  var sha1 = forge.md.sha1.create();
  var keys = forge.pki.rsa.generateKeyPair(2048);
  var big = forge.pki.rsa.generateKeyPair({ bits: 4096, e: 0x10001 });
  var sized = forge.pki.rsa.generateKeyPair(bits);
  var cipher = forge.cipher.createCipher('3DES-CBC', key);
  var des = forge.des.createEncryptionCipher(key);  // DES or 3DES by key length: not claimed
  var ed = forge.ed25519.generateKeyPair();
}

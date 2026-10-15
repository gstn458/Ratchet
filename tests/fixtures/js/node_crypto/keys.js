const crypto = require('crypto');
const { createHash: digest, publicEncrypt } = require('node:crypto');
const mine = require('./my-crypto');  // a project module, not Node's crypto

const LEGACY_HASH = 'sha1';

function hashes(data, key, name) {
  crypto.createHash('md5').update(data);
  digest(LEGACY_HASH).update(data);
  crypto.createHash('sha256').update(data);
  crypto.createHmac('SHA1', key);
  crypto.createHash(name);           // only known at run time
  mine.createHash('md5');            // not Node's crypto
}

function signing(privateKey, data) {
  crypto.createSign('RSA-SHA256').update(data).sign(privateKey);
  crypto.sign('sha256', data, privateKey);   // the key decides RSA or EC: only the hash is claimed
}

function ciphers(key, iv) {
  crypto.createCipheriv('des-ede3-cbc', key, iv);
  crypto.createCipheriv('aes-256-gcm', key, iv);
  crypto.createDecipheriv('rc4', key, null);
}

function keys() {
  crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  crypto.generateKeyPairSync('ed25519');
  crypto.generateKeyPair('x448', {}, () => {});
  publicEncrypt(publicKey, Buffer.from('secret'));
  crypto.createECDH('prime256v1');
  crypto.createDiffieHellman(2048);
}

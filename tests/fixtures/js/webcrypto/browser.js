async function webcrypto(data, spki) {
  const subtle = window.crypto.subtle;  // an alias: not followed
  await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify']);
  await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']);
  await crypto.subtle.generateKey('Ed25519', true, ['sign']);
  await crypto.subtle.digest('SHA-1', data);
  await crypto.subtle.importKey('spki', spki, { name: 'RSA-OAEP', hash: { name: 'SHA-1' } }, false, ['encrypt']);
  await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data);
  await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  await subtle.digest('SHA-1', data);
}

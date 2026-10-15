const crypto = require('crypto');

test('signs', () => {
  crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
});

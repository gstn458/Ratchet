const jwt = require('jsonwebtoken');

function issue(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'RS512' });
}

function verify(token, key) {
  return jwt.verify(token, key, { algorithms: ['ES256', `HS256`] });
}

const header = { alg: 'PBES2-HS256+A128KW', enc: 'A192GCM' };

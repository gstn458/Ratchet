import { createHash, generateKeyPairSync as gen } from 'crypto';
import * as nodeCrypto from 'node:crypto';

export const fingerprint = (data) => createHash('md5').update(data).digest('hex');
export const keyPair = () => gen('dsa', { modulusLength: 1024 });
export const ecdh = () => nodeCrypto.createECDH('secp384r1');

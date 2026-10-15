import crypto = require('crypto');
import type { KeyObject } from 'crypto';
import { generateKeyPairSync } from 'node:crypto';

const LEGACY: string = 'md5';

export function fingerprint(data: Buffer): string {
  return (crypto as any).createHash(LEGACY).update(data).digest('hex');
}

export function legacyKey(): { privateKey: KeyObject } {
  return generateKeyPairSync('rsa', { modulusLength: 1024 }) as any;
}

export function token(key: Buffer, iv: Buffer) {
  return crypto!.createCipheriv('des-ede3-cbc', key, iv) satisfies unknown;
}

interface Signer { createHash(name: string): unknown }
declare const other: Signer;
other.createHash('sha1');  // not Node's crypto

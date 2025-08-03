import { sha512 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { webcrypto } from 'node:crypto';
import * as ed from '../index.js';
// @ts-ignore
if (!globalThis.crypto) globalThis.crypto = webcrypto; // @ts-ignore
export * as ed25519 from '../index.js';
ed.hashes.sha512 = (m) => sha512(m);

export function numberToBytesLE(num, len = 32) {
  return hexToBytes(num.toString(16).padStart(len * 2, '0')).reverse();
}

export const ED25519_TORSION_SUBGROUP = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  '0000000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
];

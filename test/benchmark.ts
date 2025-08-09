import { sha512 } from '@noble/hashes/sha2.js';
import mark from 'micro-bmark';
import * as curve from '../index.ts';

(async () => {
  curve.hashes.sha512 = sha512;
  let keys, sig;
  const msg = new TextEncoder().encode('hello noble');
  await mark('init', 1, () => {
    keys = curve.keygen();
    sig = curve.sign(msg, keys.secretKey);
  });
  await mark('keygen', () => curve.keygen());
  await mark('sign', () => curve.sign(msg, keys.secretKey));
  await mark('verify', () => curve.verify(sig, msg, keys.publicKey));
  console.log();
  await mark('keygenAsync', () => curve.keygenAsync());
  await mark('signAsync', () => curve.signAsync(msg, keys.secretKey));
  await mark('verifyAsync', () => curve.verifyAsync(sig, msg, keys.publicKey));

  console.log();
  await mark('Point.fromBytes', () => curve.Point.fromBytes(keys.publicKey));
})();

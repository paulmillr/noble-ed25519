import { sha512 } from '@noble/hashes/sha2.js';
import mark from 'micro-bmark';
import * as ed from '../index.js';

(async () => {
  // warm-up
  await mark('init', 1, async () => {
    ed.utils.precompute();
    await ed.getPublicKeyAsync(ed.utils.randomPrivateKey());
  });
  ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

  function to64Bytes(numOrStr) {
    let hex = typeof numOrStr === 'string' ? numOrStr : numOrStr.toString(16);
    return ed.etc.hexToBytes(hex.padStart(64, '0'));
  }

  // const priv1bit = to64Bytes(2n);
  // prettier-ignore
  const smallPrivs = [2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n, 13n, 14n, 15n].map(a => to64Bytes(a));
  const priv = to64Bytes(0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60n);
  const msg = to64Bytes('deadbeefdeadbeefdeadbeefdeadbeefdeadbeef');
  let pubHex;
  let sigHex;
  let i = 0;
  await mark('getPublicKey 1 bit', () => {
    pubHex = ed.getPublicKey(smallPrivs[i++ % smallPrivs.length]);
  });

  await mark('getPublicKey(utils.randomPrivateKey())', () => {
    pubHex = ed.getPublicKey(ed.utils.randomPrivateKey());
  });

  await mark('sign', () => {
    sigHex = ed.sign(msg, priv);
  });
  await mark('verify', () => {
    return ed.verify(sigHex, msg, pubHex);
  });
  await mark('Point.fromHex decompression', () => {
    ed.ExtendedPoint.fromHex(pubHex);
  });

  console.log();
  await mark('getPublicKeyAsync', () => ed.getPublicKeyAsync(ed.utils.randomPrivateKey()));
  await mark('signAsync', () => ed.signAsync(msg, priv));
  await mark('verifyAsync', () => ed.verifyAsync(sigHex, msg, pubHex));
})();

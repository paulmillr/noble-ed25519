import { hexToBytes as bytes, bytesToHex as hex } from '@noble/hashes/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import * as ed from '../index.ts';
import { ED25519_TORSION_SUBGROUP, numberToBytesLE } from './ed25519.helpers.ts';
import { json } from './utils.ts';

// noble-ed25519-specific tests. Unlike ed25519.test.ts / point.test.ts, this file is NOT shared
// with noble-curves. It covers the async WebCrypto-backed API tier and implementation details:
// wNAF window boundaries, clearCofactor shortcut, strict-vs-zip215 point decoding.
// Importing ed25519.helpers.ts wires hashes.sha512 and the WebCrypto polyfill.

describe('ed25519 extras', () => {
  const P = ed.Point.CURVE().p;
  const N = ed.Point.CURVE().n;
  const G = ed.Point.BASE;

  describe('async API', () => {
    should('match sync API and RFC8032 vectors, using default WebCrypto SHA-512', async () => {
      const vectors = json('./vectors/rfc8032-ed25519.json');
      for (const v of vectors) {
        const sk = bytes(v.priv);
        const msg = bytes(v.msg);
        const pub = await ed.getPublicKeyAsync(sk);
        eql(hex(pub), v.pub, 'getPublicKeyAsync matches vector');
        eql(pub, ed.getPublicKey(sk), 'async pubkey = sync pubkey');
        const sig = await ed.signAsync(msg, sk);
        eql(hex(sig), v.sig, 'signAsync matches vector');
        eql(sig, ed.sign(msg, sk), 'async sig = sync sig');
        eql(await ed.verifyAsync(sig, msg, pub), true, 'verifyAsync accepts own sig');
        eql(ed.verify(sig, msg, pub), true, 'sync verify accepts async sig');
      }
    });
    should('keygenAsync match keygen for the same seed; reject wrong messages', async () => {
      const seed = ed.utils.randomSecretKey();
      const kA = await ed.keygenAsync(seed);
      const kS = ed.keygen(seed);
      eql(kA.secretKey, kS.secretKey);
      eql(kA.publicKey, kS.publicKey);

      const k = await ed.keygenAsync();
      eql(k.secretKey.length, 32);
      const msg = Uint8Array.of(5, 6, 7);
      const sig = await ed.signAsync(msg, k.secretKey);
      eql(await ed.verifyAsync(sig, msg, k.publicKey), true);
      eql(ed.verify(sig, msg, k.publicKey), true);
      eql(await ed.verifyAsync(sig, Uint8Array.of(5, 6), k.publicKey), false, 'wrong message');
    });
    should('verifyAsync honor the zip215 option', async () => {
      const zip215 = json('./vectors/ed25519/zip215.json');
      const v = zip215.find((v) => v.valid_zip215 && !v.valid_legacy)!;
      const msg = new TextEncoder().encode('Zcash');
      const sig = bytes(v.sig_bytes);
      const pub = bytes(v.vk_bytes);
      eql(await ed.verifyAsync(sig, msg, pub), true, 'zip215 default');
      eql(await ed.verifyAsync(sig, msg, pub, { zip215: false }), false, 'strict');
    });
  });

  describe('Point.fromBytes strict vs zip215', () => {
    should('reject non-canonical y >= p in strict mode, accept in zip215 mode', () => {
      // y = p ≡ 0 (an order-4 point) and y = p+1 ≡ 1 (the identity): both residues are valid
      // y-coordinates, only the encoding is non-canonical.
      for (const [nonCanonical, canonical] of [
        [P, 0n],
        [P + 1n, 1n],
      ]) {
        const nc = numberToBytesLE(nonCanonical, 32);
        const c = numberToBytesLE(canonical, 32);
        throws(() => ed.Point.fromBytes(nc), /out of range/);
        const pz = ed.Point.fromBytes(nc, true);
        eql(pz.equals(ed.Point.fromBytes(c, true)), true, `y=${nonCanonical} = y=${canonical}`);
      }
    });
    should('reject x=0 with sign bit set in strict mode, accept in zip215 mode', () => {
      // y = 1 gives x = 0 (identity); y = p-1 ≡ -1 gives x = 0 (the order-2 point).
      for (const y of [1n, P - 1n]) {
        const withSign = numberToBytesLE(y, 32);
        withSign[31] |= 0x80;
        throws(() => ed.Point.fromBytes(withSign), /x==0/);
        const p = ed.Point.fromBytes(withSign, true);
        eql(p.equals(ed.Point.fromBytes(numberToBytesLE(y, 32), true)), true, `-0 = 0 for y=${y}`);
      }
    });
  });

  describe('wNAF base-point multiplication', () => {
    should('match repeated-addition reference around window boundaries', () => {
      // W=8 window boundaries: digits 128/129 flip the signed-digit borrow, 256 rolls the window.
      const scalars = [
        1, 2, 3, 7, 8, 9, 127, 128, 129, 130, 191, 192, 193, 255, 256, 257, 383, 384, 385, 511, 512,
        513,
      ];
      const wanted = new Set(scalars);
      const max = Math.max(...scalars);
      let acc = G; // reference accumulator built only from add(), independent of wNAF logic
      for (let s = 1; s <= max; s++) {
        if (wanted.has(s)) {
          eql(G.multiply(BigInt(s)).equals(acc), true, `multiply(${s})`);
          eql(G.multiplyUnsafe(BigInt(s)).equals(acc), true, `multiplyUnsafe(${s})`);
        }
        acc = acc.add(G);
      }
    });
    should('match doubling-chain reference for 2^k, all-ones and N-1 scalars', () => {
      let d = G; // reference built only from double()
      for (let k = 1; k <= 252; k++) {
        d = d.double();
        const s = 1n << BigInt(k);
        if (s < N) eql(G.multiply(s).equals(d), true, `multiply(2^${k})`);
      }
      // d = [2^252]G now. The all-ones scalar carries through every window, incl. the 33rd.
      const allOnes = (1n << 252n) - 1n;
      eql(G.multiply(allOnes).add(G).equals(d), true, '[2^252-1]G + G = [2^252]G');
      eql(G.multiply(N - 1n).equals(G.negate()), true, '[N-1]G = -G');
    });
  });

  describe('clearCofactor', () => {
    should('equal multiplyUnsafe(8) and annihilate the torsion subgroup', () => {
      const { point } = ed.utils.getExtendedPublicKey(ed.utils.randomSecretKey());
      eql(point.clearCofactor().equals(point.multiplyUnsafe(8n)), true, '[8]P via doublings');
      eql(ed.Point.ZERO.clearCofactor().equals(ed.Point.ZERO), true, '[8]0 = 0');
      eql(point.isSmallOrder(), false, 'prime-order point is not small-order');
      for (const thex of ED25519_TORSION_SUBGROUP) {
        const T = ed.Point.fromBytes(bytes(thex), true);
        eql(T.isSmallOrder(), true, `torsion isSmallOrder: ${thex}`);
        eql(
          point.add(T).clearCofactor().equals(point.clearCofactor()),
          true,
          `[8](P+T) = [8]P: ${thex}`
        );
      }
    });
  });
});

should.runWhen(import.meta.url);

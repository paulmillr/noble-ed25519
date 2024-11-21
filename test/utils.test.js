import { deepStrictEqual, throws } from 'assert';
import * as fc from 'fast-check';
import { describe, should } from 'micro-should';
import * as items from '../index.js';
import { TYPE_TEST } from './utils.js';
const { bytesToHex, concatBytes, hexToBytes, mod, invert } = items.etc;

describe('utils', () => {
  const staticHexVectors = [
    { bytes: Uint8Array.from([]), hex: '' },
    { bytes: Uint8Array.from([0xbe]), hex: 'be' },
    { bytes: Uint8Array.from([0xca, 0xfe]), hex: 'cafe' },
    { bytes: Uint8Array.from(new Array(1024).fill(0x69)), hex: '69'.repeat(1024) },
  ];
  should('hexToBytes', () => {
    for (let v of staticHexVectors) deepStrictEqual(hexToBytes(v.hex), v.bytes);
    for (let v of staticHexVectors) deepStrictEqual(hexToBytes(v.hex.toUpperCase()), v.bytes);
    for (let v of TYPE_TEST.hex) {
      throws(() => hexToBytes(v));
    }
  });
  should('bytesToHex', () => {
    for (let v of staticHexVectors) deepStrictEqual(bytesToHex(v.bytes), v.hex);
    for (let v of TYPE_TEST.bytes) {
      throws(() => bytesToHex(v));
    }
  });
  should('hexToBytes <=> bytesToHex roundtrip', () =>
    fc.assert(
      fc.property(fc.hexaString({ minLength: 2, maxLength: 64 }), (hex) => {
        if (hex.length % 2 !== 0) return;
        deepStrictEqual(hex, bytesToHex(hexToBytes(hex)));
        deepStrictEqual(hex, bytesToHex(hexToBytes(hex.toUpperCase())));
        deepStrictEqual(hexToBytes(hex), Uint8Array.from(Buffer.from(hex, 'hex')));
      })
    )
  );
  should('concatBytes', () => {
    const a = 1;
    const b = 2;
    const c = 0xff;
    const aa = Uint8Array.from([a]);
    const bb = Uint8Array.from([b]);
    const cc = Uint8Array.from([c]);
    deepStrictEqual(concatBytes(), new Uint8Array());
    deepStrictEqual(concatBytes(aa, bb), Uint8Array.from([a, b]));
    deepStrictEqual(concatBytes(aa, bb, cc), Uint8Array.from([a, b, c]));
    for (let v of TYPE_TEST.bytes)
      throws(() => {
        concatBytes(v);
      });
  });
  should('concatBytes random', () =>
    fc.assert(
      fc.property(fc.uint8Array(), fc.uint8Array(), fc.uint8Array(), (a, b, c) => {
        const expected = Uint8Array.from(Buffer.concat([a, b, c]));
        deepStrictEqual(concatBytes(a.slice(), b.slice(), c.slice()), expected);
      })
    )
  );
});

describe('utils math', () => {
  should('mod', () => {
    deepStrictEqual(mod(11n, 10n), 1n);
    deepStrictEqual(mod(-1n, 10n), 9n);
    deepStrictEqual(mod(0n, 10n), 0n);
  });
  should('invert', () => {
    deepStrictEqual(invert(512n, 1023n), 2n);
    deepStrictEqual(
      invert(2n ** 255n, 2n ** 255n - 19n),
      21330121701610878104342023554231983025602365596302209165163239159352418617876n
    );
    throws(() => {
      invert();
    });
    throws(() => {
      invert(1n);
    }); // no default modulus
    throws(() => {
      invert(0n, 12n);
    });
    throws(() => {
      invert(1n, -12n);
    });
    throws(() => {
      invert(512n, 1023);
    });
    throws(() => {
      invert(512, 1023n);
    });
  });
});

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}

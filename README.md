# noble-ed25519

[Fastest](#speed) 4KB JS implementation of [ed25519](https://en.wikipedia.org/wiki/EdDSA)
elliptic curve. Auditable, high-security, 0-dependency EdDSA signatures compliant with
[RFC8032](https://tools.ietf.org/html/rfc8032) and [ZIP215](https://zips.z.cash/zip-0215).

The library is a tiny single-feature version of
[noble-curves](https://github.com/paulmillr/noble-curves), with some features
removed. Check out curves as a drop-in replacement with
[ristretto255](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448),
X25519 / curve25519, ed25519ph and ed25519ctx.

Take a look at: [Upgrading](#upgrading) section for v1 to v2 transition instructions,
[the online demo](https://paulmillr.com/noble/) and
[ed25519-keygen](https://github.com/paulmillr/ed25519-keygen) if you need
SSH/PGP/HDKey implementation using the library.

### This library belongs to _noble_ crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies, protection against supply chain attacks
- Auditable TypeScript / JS code
- Supported in all major browsers and stable node.js versions
- All releases are signed with PGP keys
- Check out [homepage](https://paulmillr.com/noble/) & all libraries:
  [curves](https://github.com/paulmillr/noble-curves)
  (4kb versions [secp256k1](https://github.com/paulmillr/noble-secp256k1),
  [ed25519](https://github.com/paulmillr/noble-ed25519)),
  [hashes](https://github.com/paulmillr/noble-hashes)

## Usage

Browser, deno, node.js and unpkg are supported:

> npm install @noble/ed25519

```js
import * as ed from '@noble/ed25519'; // ESM-only. Use bundler for common.js
// import * as ed from "https://deno.land/x/ed25519/mod.ts"; // Deno
// import * as ed from "https://unpkg.com/@noble/ed25519"; // Unpkg
(async () => {
  // keys, messages & other inputs can be Uint8Arrays or hex strings
  // Uint8Array.from([0xde, 0xad, 0xbe, 0xef]) === 'deadbeef'
  const privKey = ed.utils.randomPrivateKey(); // Secure random private key
  const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
  const pubKey = await ed.getPublicKeyAsync(privKey);
  const signature = await ed.signAsync(message, privKey);
  const isValid = await ed.verifyAsync(signature, message, pubKey);
})();
```

Advanced examples:

```ts
// 1. Use the shim to enable synchronous methods.
// Only async methods are available by default to keep library dependency-free.
import { sha512 } from '@noble/hashes/sha512';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
ed.getPublicKey(privateKey); // sync methods can be used now
ed.sign(message, privateKey);
ed.verify(signature, message, publicKey);

// 2. Use the shim only for node.js <= 18 BEFORE importing noble-secp256k1.
// The library depends on global variable crypto to work. It is available in
// all browsers and many environments, but node.js <= 18 don't have it.
import { webcrypto } from 'node:crypto';
// @ts-ignore
if (!globalThis.crypto) globalThis.crypto = webcrypto;
```

## API

There are 3 main methods: `getPublicKey(privateKey)`, `sign(message, privateKey)`
and `verify(signature, message, publicKey)`.

```typescript
type Hex = Uint8Array | string;
// Generates 32-byte public key from 32-byte private key.
// - Some libraries have 64-byte private keys. Don't worry, those are just
//   priv+pub concatenated. Slice it: `priv64b.slice(0, 32)`
// - Use `Point.fromPrivateKey(privateKey)` if you want `Point` instance instead
// - Use `Point.fromHex(publicKey)` if you want to convert hex / bytes into Point.
//   It will use decompression algorithm 5.1.3 of RFC 8032.
// - Use `utils.getExtendedPublicKey` if you need full SHA512 hash of seed
function getPublicKey(privateKey: Hex): Uint8Array;
function getPublicKeyAsync(privateKey: Hex): Promise<Uint8Array>;

// Generates EdDSA signature.
function sign(
  message: Hex, // message which would be signed
  privateKey: Hex // 32-byte private key
): Uint8Array;
function signAsync(message: Hex, privateKey: Hex): Promise<Uint8Array>;

// Verifies EdDSA signature. Compatible with [ZIP215](https://zips.z.cash/zip-0215):
// - `0 <= sig.R/publicKey < 2**256` (can be `>= curve.P` aka non-canonical encoding)
// - `0 <= sig.s < l`
// - There is no security risk in ZIP behavior, and there is no effect on
//   honestly generated sigs, but it is verify important for consensus-critical
//   apps. See [It’s 255:19AM](https://hdevalence.ca/blog/2020-10-04-its-25519am).
// - _Not compatible with RFC8032_ because RFC enforces canonical encoding of
//   R/publicKey.
function verify(
  signature: Hex, // returned by the `sign` function
  message: Hex, // message that needs to be verified
  publicKey: Hex // public (not private) key
): boolean;
function verifyAsync(signature: Hex, message: Hex, publicKey: Hex): Promise<boolean>;
```

A bunch of useful **utilities** are also exposed:

```typescript
export const etc: {
    bytesToHex: (b: Bytes) => string;
    hexToBytes: (hex: string) => Bytes;
    concatBytes: (...arrs: Bytes[]) => Uint8Array;
    mod: (a: bigint, b?: bigint) => bigint;
    invert: (num: bigint, md?: bigint) => bigint;
    randomBytes: (len: number) => Bytes;
    sha512Async: (...messages: Bytes[]) => Promise<Bytes>;
    sha512Sync: Sha512FnSync;
};
export const utils: {
    getExtendedPublicKeyAsync: (priv: Hex) => Promise<ExtK>;
    getExtendedPublicKey: (priv: Hex) => ExtK;
    precompute(p: Point, w?: number): Point;
    randomPrivateKey: () => Bytes;
};

export class ExtendedPoint { // Elliptic curve point in Extended (x, y, z, t) coordinates.
  constructor(x: bigint, y: bigint, z: bigint, t: bigint);
  static fromAffine(point: AffinePoint): ExtendedPoint;
  static fromHex(hash: string);
  toRawBytes(): Uint8Array;
  toHex(): string; // Compact representation of a Point
  isTorsionFree(): boolean; // Multiplies the point by curve order
  toAffine(): Point;
  equals(other: ExtendedPoint): boolean;
  // Note: It does not check whether the `other` point is valid point on curve.
  add(other: ExtendedPoint): ExtendedPoint;
  subtract(other: ExtendedPoint): ExtendedPoint;
  multiply(scalar: bigint): ExtendedPoint;
}
// Curve params
ed25519.CURVE.p // 2 ** 255 - 19
ed25519.CURVE.n // 2 ** 252 + 27742317777372353535851937790883648493
ed25519.ExtendedPoint.BASE // new ed25519.Point(Gx, Gy) where
// Gx=15112221349535400772501151409588531511454012693041857206046113283949847762202n
// Gy=46316835694926478169428394003475163141307993866256225615783033603165251855960n;
```

## Security

The module is production-ready.
It is cross-tested against [noble-curves](https://github.com/paulmillr/noble-curves),
and has similar security.

1. The current version is rewrite of v1, which has been audited by cure53:
[PDF](https://cure53.de/pentest-report_ed25519.pdf). 
2. It's being fuzzed by [Guido Vranken's cryptofuzz](https://github.com/guidovranken/cryptofuzz):
run the fuzzer by yourself to check.

Our EC multiplication is hardened to be algorithmically constant time.
We're using built-in JS `BigInt`, which is potentially vulnerable to
[timing attacks](https://en.wikipedia.org/wiki/Timing_attack) as
[per MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt#cryptography).
But, _JIT-compiler_ and _Garbage Collector_ make "constant time" extremely hard
to achieve in a scripting language. Which means _any other JS library doesn't
use constant-time bigints_. Including bn.js or anything else.
Even statically typed Rust, a language without GC,
[makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security)
for some cases. If your goal is absolute security, don't use any JS lib —
including bindings to native ones. Use low-level libraries & languages.

We consider infrastructure attacks like rogue NPM modules very important;
that's why it's crucial to minimize the amount of 3rd-party dependencies & native
bindings. If your app uses 500 dependencies, any dep could get hacked and you'll
be downloading malware with every `npm install`. Our goal is to minimize this attack vector.

## Speed

Benchmarks done with Apple M2 on macOS 13 with Node.js 19.

    getPublicKey 1 bit x 8,260 ops/sec @ 121μs/op
    getPublicKey(utils.randomPrivateKey()) x 8,096 ops/sec @ 123μs/op
    sign x 4,084 ops/sec @ 244μs/op
    verify x 872 ops/sec @ 1ms/op
    Point.fromHex decompression x 14,523 ops/sec @ 68μs/op

Compare to alternative implementations:

    tweetnacl@1.0.3 getPublicKey x 1,808 ops/sec @ 552μs/op ± 1.64%
    tweetnacl@1.0.3 sign x 651 ops/sec @ 1ms/op
    ristretto255@0.1.2 getPublicKey x 640 ops/sec @ 1ms/op ± 1.59%
    sodium-native#sign x 83,654 ops/sec @ 11μs/op

## Contributing

1. Clone the repository
2. `npm install` to install build dependencies like TypeScript
3. `npm run build` to compile TypeScript code
4. `npm run test` to run jest on `test/index.ts`

## Upgrading

noble-ed25519 v2 features improved security and smaller attack surface.
The goal of v2 is to provide minimum possible JS library which is safe and fast.

That means the library was reduced 4x, to just over 300 lines. In order to
achieve the goal, **some features were moved** to
[noble-curves](https://github.com/paulmillr/noble-curves), which is
even safer and faster drop-in replacement library with same API.
Switch to curves if you intend to keep using these features:

- x25519 / curve25519 / getSharedSecret
- ristretto255 / RistrettoPoint
- Using `utils.precompute()` for non-base point
- Support for environments which don't support bigint literals
- Common.js support
- Support for node.js 18 and older without [shim](#usage)

Other changes for upgrading from @noble/ed25519 1.7 to 2.0:

- Methods are now sync by default; use `getPublicKeyAsync`, `signAsync`, `verifyAsync` for async versions
- `bigint` is no longer allowed in `getPublicKey`, `sign`, `verify`. Reason: ed25519 is LE, can lead to bugs
- `Point` (2d xy) has been changed to `ExtendedPoint` (xyzt)
- `Signature` was removed: just use raw bytes or hex now
- `utils` were split into `utils` (same api as in noble-curves) and
  `etc` (`sha512Sync` and others)

## License

MIT (c) 2019 Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.

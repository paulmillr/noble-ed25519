# noble-ed25519

Fastest 4KB JS implementation of ed25519 signatures.

- ✍️ [EDDSA](https://en.wikipedia.org/wiki/EdDSA) signatures compliant with [RFC8032](https://tools.ietf.org/html/rfc8032),
  FIPS 186-5
- 🪢 Consensus-friendly, compliant with [ZIP215](https://zips.z.cash/zip-0215)
- 🔖 SUF-CMA (strong unforgeability under chosen message attacks) and SBS (non-repudiation / exclusive ownership)
- 📦 Pure ESM, can be imported without transpilers
- 🪶 4KB gzipped, 350 lines of code

The module is a sister project of [noble-curves](https://github.com/paulmillr/noble-curves),
focusing on smaller attack surface & better auditability.
Curves are drop-in replacement and have more features: Common.js, ristretto255, X25519, curve25519, ed25519ph. To upgrade from v1 to v2, see [Upgrading](#upgrading).

### This library belongs to _noble_ cryptography

> **noble-cryptography** — high-security, easily auditable set of contained cryptographic libraries and tools.

- Zero or minimal dependencies
- Highly readable TypeScript / JS code
- PGP-signed releases and transparent NPM builds with provenance
- Check out [homepage](https://paulmillr.com/noble/) & all libraries:
  [ciphers](https://github.com/paulmillr/noble-ciphers),
  [curves](https://github.com/paulmillr/noble-curves),
  [hashes](https://github.com/paulmillr/noble-hashes),
  [post-quantum](https://github.com/paulmillr/noble-post-quantum),
  4kb [secp256k1](https://github.com/paulmillr/noble-secp256k1) /
  [ed25519](https://github.com/paulmillr/noble-ed25519)

## Usage

> `npm install @noble/ed25519`

> `deno add @noble/ed25519`

We support all major platforms and runtimes. For node.js <= 18 and React Native, additional polyfills are needed: see below.

```js
import * as ed from '@noble/ed25519';
// import * as ed from "https://unpkg.com/@noble/ed25519"; // Unpkg
(async () => {
  // Uint8Arrays or hex strings are accepted:
  // Uint8Array.from([0xde, 0xad, 0xbe, 0xef]) is equal to 'deadbeef'
  const privKey = ed.utils.randomPrivateKey(); // Secure random private key
  const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
  const pubKey = await ed.getPublicKeyAsync(privKey); // Sync methods below
  const signature = await ed.signAsync(message, privKey);
  const isValid = await ed.verifyAsync(signature, message, pubKey);
})();
```

Additional polyfills for some environments:

```ts
// 1. Enable synchronous methods.
// Only async methods are available by default, to keep the library dependency-free.
import { sha512 } from '@noble/hashes/sha512';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
// Sync methods can be used now:
// ed.getPublicKey(privKey); ed.sign(msg, privKey); ed.verify(signature, msg, pubKey);

// 2. node.js 18 and older, requires polyfilling globalThis.crypto
import { webcrypto } from 'node:crypto';
// @ts-ignore
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// 3. React Native needs crypto.getRandomValues polyfill and sha512
import 'react-native-get-random-values';
import { sha512 } from '@noble/hashes/sha512';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
ed.etc.sha512Async = (...m) => Promise.resolve(ed.etc.sha512Sync(...m));
```

## API

There are 3 main methods: `getPublicKey(privateKey)`, `sign(message, privateKey)`
and `verify(signature, message, publicKey)`. We accept Hex type everywhere:

```ts
type Hex = Uint8Array | string;
```

### getPublicKey

```typescript
function getPublicKey(privateKey: Hex): Uint8Array;
function getPublicKeyAsync(privateKey: Hex): Promise<Uint8Array>;
```

Generates 32-byte public key from 32-byte private key.

- Some libraries have 64-byte private keys. Don't worry, those are just
  priv+pub concatenated. Slice it: `priv64b.slice(0, 32)`
- Use `Point.fromPrivateKey(privateKey)` if you want `Point` instance instead
- Use `Point.fromHex(publicKey)` if you want to convert hex / bytes into Point.
  It will use decompression algorithm 5.1.3 of RFC 8032.
- Use `utils.getExtendedPublicKey` if you need full SHA512 hash of seed

### sign

```ts
function sign(
  message: Hex, // message which would be signed
  privateKey: Hex // 32-byte private key
): Uint8Array;
function signAsync(message: Hex, privateKey: Hex): Promise<Uint8Array>;
```

Generates EdDSA signature. Always deterministic.

Assumes unhashed `message`: it would be hashed by ed25519 internally.
For prehashed ed25519ph, switch to noble-curves.

### verify

```ts
function verify(
  signature: Hex, // returned by the `sign` function
  message: Hex, // message that needs to be verified
  publicKey: Hex // public (not private) key,
  options = { zip215: true } // ZIP215 or RFC8032 verification type
): boolean;
function verifyAsync(signature: Hex, message: Hex, publicKey: Hex): Promise<boolean>;
```

Verifies EdDSA signature. Has SUF-CMA (strong unforgeability under chosen message attacks).
By default, follows ZIP215 [1] and can be used in consensus-critical apps [2].
`zip215: false` option switches verification criteria to strict
RFC8032 / FIPS 186-5 and provides non-repudiation with SBS (Strongly Binding Signatures) [3].

[1]: https://zips.z.cash/zip-0215
[2]: https://hdevalence.ca/blog/2020-10-04-its-25519am
[3]: https://eprint.iacr.org/2020/1244

### utils

A bunch of useful **utilities** are also exposed:

```typescript
const etc: {
  bytesToHex: (b: Bytes) => string;
  hexToBytes: (hex: string) => Bytes;
  concatBytes: (...arrs: Bytes[]) => Uint8Array;
  mod: (a: bigint, b?: bigint) => bigint;
  invert: (num: bigint, md?: bigint) => bigint;
  randomBytes: (len: number) => Bytes;
  sha512Async: (...messages: Bytes[]) => Promise<Bytes>;
  sha512Sync: Sha512FnSync;
};
const utils: {
  getExtendedPublicKeyAsync: (priv: Hex) => Promise<ExtK>;
  getExtendedPublicKey: (priv: Hex) => ExtK;
  precompute(p: Point, w?: number): Point;
  randomPrivateKey: () => Bytes; // Uses CSPRNG https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
};

class ExtendedPoint {
  // Elliptic curve point in Extended (x, y, z, t) coordinates.
  constructor(ex: bigint, ey: bigint, ez: bigint, et: bigint);
  static readonly BASE: Point;
  static readonly ZERO: Point;
  static fromAffine(point: AffinePoint): ExtendedPoint;
  static fromHex(hash: string);
  get x(): bigint;
  get y(): bigint;
  // Note: It does not check whether the `other` point is valid point on curve.
  add(other: ExtendedPoint): ExtendedPoint;
  equals(other: ExtendedPoint): boolean;
  isTorsionFree(): boolean; // Multiplies the point by curve order
  multiply(scalar: bigint): ExtendedPoint;
  subtract(other: ExtendedPoint): ExtendedPoint;
  toAffine(): Point;
  toRawBytes(): Uint8Array;
  toHex(): string; // Compact representation of a Point
}
// Curve params
ed25519.CURVE.p; // 2 ** 255 - 19
ed25519.CURVE.n; // 2 ** 252 + 27742317777372353535851937790883648493
ed25519.ExtendedPoint.BASE; // new ed25519.Point(Gx, Gy) where
// Gx=15112221349535400772501151409588531511454012693041857206046113283949847762202n
// Gy=46316835694926478169428394003475163141307993866256225615783033603165251855960n;
```

## Security

The module is production-ready.
While [noble-curves](https://github.com/paulmillr/noble-curves) provide improved security,
we cross-test against curves.

1. The current version has not been independently audited. It is a rewrite of v1, which has been audited by cure53 in Feb 2022:
   [PDF](https://cure53.de/pentest-report_ed25519.pdf).
2. It's being fuzzed by [Guido Vranken's cryptofuzz](https://github.com/guidovranken/cryptofuzz):
   you can also run the fuzzer by yourself.

### Constant-timeness

_JIT-compiler_ and _Garbage Collector_ make "constant time" extremely hard to
achieve [timing attack](https://en.wikipedia.org/wiki/Timing_attack) resistance
in a scripting language. Which means _any other JS library can't have
constant-timeness_. Even statically typed Rust, a language without GC,
[makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security)
for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones.
Use low-level libraries & languages. Nonetheless we're targetting algorithmic constant time.

### Supply chain security

1. **Commits** are signed with PGP keys, to prevent forgery. Make sure to verify commit signatures.
2. **Releases** are transparent and built on GitHub CI. Make sure to verify [provenance](https://docs.npmjs.com/generating-provenance-statements) logs
3. **Rare releasing** is followed.
   The less often it is done, the less code dependents would need to audit
4. **Dependencies** are minimal:
   - All deps are prevented from automatic updates and have locked-down version ranges. Every update is checked with `npm-diff`
   - Updates themselves are rare, to ensure rogue updates are not catched accidentally
5. devDependencies are only used if you want to contribute to the repo. They are disabled for end-users:
   - [noble-hashes](https://github.com/paulmillr/noble-hashes) is used, by the same author, to provide hashing functionality tests
   - micro-bmark and micro-should are developed by the same author and follow identical security practices
   - fast-check (property-based testing) and typescript are used for code quality, vector generation and ts compilation.
     The packages are big, which makes it hard to audit their source code thoroughly and fully

We consider infrastructure attacks like rogue NPM modules very important;
that's why it's crucial to minimize the amount of 3rd-party dependencies & native bindings.
If your app uses 500 dependencies, any dep could get hacked and you'll be
downloading malware with every install. Our goal is to minimize this attack vector.

If you see anything unusual: investigate and report.

### Randomness

We're deferring to built-in
[crypto.getRandomValues](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues)
which is considered cryptographically secure (CSPRNG).

In the past, browsers had bugs that made it weak: it may happen again.

## Speed

Benchmarks done with Apple M2 on macOS 13 with Node.js 20.

    getPublicKey(utils.randomPrivateKey()) x 9,173 ops/sec @ 109μs/op
    sign x 4,567 ops/sec @ 218μs/op
    verify x 994 ops/sec @ 1ms/op
    Point.fromHex decompression x 16,164 ops/sec @ 61μs/op

Compare to alternative implementations:

    tweetnacl@1.0.3 getPublicKey x 1,808 ops/sec @ 552μs/op ± 1.64%
    tweetnacl@1.0.3 sign x 651 ops/sec @ 1ms/op
    ristretto255@0.1.2 getPublicKey x 640 ops/sec @ 1ms/op ± 1.59%
    sodium-native#sign x 83,654 ops/sec @ 11μs/op

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

## Contributing & testing

* `npm install && npm run build && npm test` will build the code and run tests.
* `npm run bench` will run benchmarks, which may need their deps first (`npm run bench:install`)
* `npm run loc` will count total output size, important to be less than 4KB

Check out [github.com/paulmillr/guidelines](https://github.com/paulmillr/guidelines)
for general coding practices and rules.

See [paulmillr.com/noble](https://paulmillr.com/noble/)
for useful resources, articles, documentation and demos
related to the library.

## License

MIT (c) 2019 Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.

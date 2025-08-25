# noble-ed25519

Fastest 5KB JS implementation of ed25519 signatures.

- ✍️ [EDDSA](https://en.wikipedia.org/wiki/EdDSA) signatures compliant with
  [RFC8032](https://tools.ietf.org/html/rfc8032), FIPS 186-5
- 🪢 Consensus-friendly, compliant with [ZIP215](https://zips.z.cash/zip-0215)
- 🔖 SUF-CMA (strong unforgeability under chosen message attacks) and
  SBS (non-repudiation / exclusive ownership)
- 🪶 3.66KB (gzipped)

The module is a sister project of [noble-curves](https://github.com/paulmillr/noble-curves),
focusing on smaller attack surface & better auditability.
Curves are drop-in replacement and have more features: ristretto255, x25519 / curve25519, ed25519ph, hash-to-curve, oprf. To upgrade from v1 to v2, see [Upgrading](#upgrading).

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
  5KB [secp256k1](https://github.com/paulmillr/noble-secp256k1) /
  [ed25519](https://github.com/paulmillr/noble-ed25519)

## Usage

> `npm install @noble/ed25519`

> `deno add jsr:@noble/ed25519`

We support all major platforms and runtimes. For node.js <= 18 and React Native, additional polyfills are needed: see below.

```js
import * as ed from '@noble/ed25519';
(async () => {
  const { secretKey, publicKey } = await ed.keygenAsync();
  // const publicKey = await ed.getPublicKeyAsync(secretKey);
  const message = new TextEncoder().encode('hello noble');
  const signature = await ed.signAsync(message, secretKey);
  const isValid = await ed.verifyAsync(signature, message, publicKey);
})();
```

### Enabling synchronous methods

Only async methods are available by default, to keep the library dependency-free.
To enable sync methods:

```ts
import { sha512 } from '@noble/hashes/sha2.js';
ed.hashes.sha512 = sha512;
// Sync methods can be used now:
const { secretKey, publicKey } = ed.keygen();
// const publicKey = ed.getPublicKey(secretKey);
const sig = ed.sign(msg, secretKey);
const isValid = ed.verify(sig, msg, publicKey);
```

### React Native: polyfill getRandomValues and sha512

```ts
import 'react-native-get-random-values';
import { sha512 } from '@noble/hashes/sha2.js';
ed.hashes.sha512 = sha512;
ed.hashes.sha512Async = (m: Uint8Array) => Promise.resolve(sha512(m));
```

## API

There are 4 main methods, which accept Uint8Array-s:

- `keygen()` and `keygenAsync()`
- `getPublicKey(secretKey)` and `getPublicKeyAsync(secretKey)`
- `sign(message, secretKey)` and `signAsync(message, secretKey)`
- `verify(signature, message, publicKey)` and `verifyAsync(signature, message, publicKey)`

### keygen

```typescript
import * as ed from '@noble/ed25519';
(async () => {
  const keys = ed.keygen(); // needs ed.hashes.sha512
  const { secretKey, publicKey } = keys
  const keysA = await ed.keygenAsync();
})();
```

### getPublicKey

```typescript
import * as ed from '@noble/ed25519';
(async () => {
  const pubKey = ed.getPublicKey(secretKeyA); // needs ed.hashes.sha512
  const pubKeyA = await ed.getPublicKeyAsync(secretKeyA);
  const pubKeyPoint = ed.Point.fromBytes(pubKeyB);
  const pubKeyExtended = ed.utils.getExtendedPublicKey(secretKeyA);
})();
```

Generates 32-byte public key from 32-byte private key.

- Some libraries have 64-byte private keys - those are just priv+pub concatenated
- Use `ExtendedPoint.fromHex(publicKey)` if you want to convert hex / bytes into Point.
  It will use decompression algorithm 5.1.3 of RFC 8032.
- Use `utils.getExtendedPublicKey` if you need full SHA512 hash of seed

### sign

```ts
import * as ed from '@noble/ed25519';
(async () => {
  const { secretKey, publicKey } = ed.keygen();
  const message = new TextEncoder().encode('hello noble');
  const signature = ed.sign(message, secretKey);
  const signatureA = await ed.signAsync(message, secretKey);
})();
```

Generates deterministic EdDSA signature. `message` would be hashed by ed25519 internally.
For prehashed ed25519ph, switch to noble-curves.

### verify

```ts
import * as ed from '@noble/ed25519';
(async () => {
  const { secretKey, publicKey } = ed.keygen();
  const message = new TextEncoder().encode('hello noble');
  const signature = ed.sign(message, secretKey);
  const isValid = ed.verify(signature, message, pubKey);

  const isValidFips = ed.verify(signature, message, pubKey, { zip215: false });
  const isValidA = await ed.verifyAsync(signature, message, pubKey);
})();
```

Verifies EdDSA signature. Has SUF-CMA (strong unforgeability under chosen message attacks).
By default, follows ZIP215 [^1] and can be used in consensus-critical apps [^2].
`zip215: false` option switches verification criteria to strict
RFC8032 / FIPS 186-5 and provides non-repudiation with SBS (Strongly Binding Signatures) [^3].

### utils

A bunch of useful **utilities** are also exposed:

```typescript
import * as ed from '@noble/ed25519';
const { bytesToHex, hexToBytes, concatBytes, mod, invert, randomBytes } = ed.etc;
const { getExtendedPublicKey, getExtendedPublicKeyAsync, randomSecretKey } = ed.utils;
const { Point } = ed;
console.log(Point.CURVE(), Point.BASE);
/*
class Point {
  static BASE: Point;
  static ZERO: Point;
  readonly X: bigint;
  readonly Y: bigint;
  readonly Z: bigint;
  readonly T: bigint;
  constructor(X: bigint, Y: bigint, Z: bigint, T: bigint);
  static CURVE(): EdwardsOpts;
  static fromAffine(p: AffinePoint): Point;
  static fromBytes(hex: Bytes, zip215?: boolean): Point;
  static fromHex(hex: string, zip215?: boolean): Point;
  get x(): bigint;
  get y(): bigint;
  assertValidity(): this;
  equals(other: Point): boolean;
  is0(): boolean;
  negate(): Point;
  double(): Point;
  add(other: Point): Point;
  subtract(other: Point): Point;
  multiply(n: bigint, safe?: boolean): Point;
  multiplyUnsafe(scalar: bigint): Point;
  toAffine(): AffinePoint;
  toBytes(): Bytes;
  toHex(): string;
  clearCofactor(): Point;
  isSmallOrder(): boolean;
  isTorsionFree(): boolean;
}
*/
```

## Security

The module is production-ready.

We cross-test against sister project [noble-curves](https://github.com/paulmillr/noble-curves), which was audited and provides improved security.

- The current version has not been independently audited. It is a rewrite of v1, which has been audited by cure53 in Feb 2022:
  [PDF](https://cure53.de/pentest-report_ed25519.pdf).
- It's being fuzzed [in a separate repository](https://github.com/paulmillr/fuzzing)

If you see anything unusual: investigate and report.

### Constant-timeness

We're targetting algorithmic constant time. _JIT-compiler_ and _Garbage Collector_ make "constant time"
extremely hard to achieve [timing attack](https://en.wikipedia.org/wiki/Timing_attack) resistance
in a scripting language. Which means _any other JS library can't have
constant-timeness_. Even statically typed Rust, a language without GC,
[makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security)
for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones.
Use low-level libraries & languages.

### Supply chain security

- **Commits** are signed with PGP keys, to prevent forgery. Make sure to verify commit signatures
- **Releases** are transparent and built on GitHub CI.
  Check out [attested checksums of single-file builds](https://github.com/paulmillr/noble-ed25519/attestations)
  and [provenance logs](https://github.com/paulmillr/noble-ed25519/actions/workflows/release.yml)
- **Rare releasing** is followed to ensure less re-audit need for end-users
- **Dependencies** are minimized and locked-down: any dependency could get hacked and users will be downloading malware with every install.
  - We make sure to use as few dependencies as possible
  - Automatic dep updates are prevented by locking-down version ranges; diffs are checked with `npm-diff`
- **Dev Dependencies** are disabled for end-users; they are only used to develop / build the source code

For this package, there are 0 dependencies; and a few dev dependencies:

- [noble-hashes](https://github.com/paulmillr/noble-hashes) provides cryptographic hashing functionality
- micro-bmark, micro-should and jsbt are used for benchmarking / testing / build tooling and developed by the same author
- prettier, fast-check and typescript are used for code quality / test generation / ts compilation. It's hard to audit their source code thoroughly and fully because of their size

### Randomness

We're deferring to built-in
[crypto.getRandomValues](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues)
which is considered cryptographically secure (CSPRNG).

In the past, browsers had bugs that made it weak: it may happen again.
Implementing a userspace CSPRNG to get resilient to the weakness
is even worse: there is no reliable userspace source of quality entropy.

### Quantum computers

Cryptographically relevant quantum computer, if built, will allow to
break elliptic curve cryptography (both ECDSA / EdDSA & ECDH) using Shor's algorithm.

Consider switching to newer / hybrid algorithms, such as SPHINCS+. They are available in
[noble-post-quantum](https://github.com/paulmillr/noble-post-quantum).

NIST prohibits classical cryptography (RSA, DSA, ECDSA, ECDH) [after 2035](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf). Australian ASD prohibits it [after 2030](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism/cyber-security-guidelines/guidelines-cryptography).

## Speed

    npm run bench

Benchmarks measured with Apple M4.

    init 11ms
    keygen x 11,253 ops/sec @ 88μs/op
    sign x 5,891 ops/sec @ 169μs/op
    verify x 1,281 ops/sec @ 780μs/op

    keygenAsync x 10,205 ops/sec @ 97μs/op
    signAsync x 4,985 ops/sec @ 200μs/op
    verifyAsync x 1,286 ops/sec @ 777μs/op

    Point.fromBytes x 22,811 ops/sec @ 43μs/op

Compare to alternative implementations:

    tweetnacl@1.0.3 getPublicKey x 1,808 ops/sec @ 552μs/op ± 1.64%
    tweetnacl@1.0.3 sign x 651 ops/sec @ 1ms/op
    ristretto255@0.1.2 getPublicKey x 640 ops/sec @ 1ms/op ± 1.59%
    sodium-native#sign x 83,654 ops/sec @ 11μs/op

## Upgrading

### v2 to v3

v3 brings the package closer to noble-curves v2.

- Most methods now expect Uint8Array, string hex inputs are prohibited
- Add `keygen`, `keygenAsync` method
- Node v20.19 is now the minimum required version
- Various small changes for types and Point class
- etc: hashes are now set in `hashes` object:

```js
// before
ed.etc.sha512 = sha512;
ed.etc.sha512Async = (m: Uint8Array) => Promise.resolve(sha512(m));
// after
ed.hashes.sha512 = sha512;
ed.hashes.sha512Async = (m: Uint8Array) => Promise.resolve(sha512(m));
```

### v1 to v2

v2 features improved security and smaller attack surface.
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

- `npm install && npm run build && npm test` will build the code and run tests.
- `npm run bench` will run benchmarks
- `npm run build:release` will build single file

See [paulmillr.com/noble](https://paulmillr.com/noble/)
for useful resources, articles, documentation and demos
related to the library.

## License

The MIT License (MIT)

Copyright (c) 2019 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.

[^1]: https://zips.z.cash/zip-0215

[^2]: https://hdevalence.ca/blog/2020-10-04-its-25519am

[^3]: https://eprint.iacr.org/2020/1244

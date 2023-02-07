# noble-ed25519 ![Node CI](https://github.com/paulmillr/noble-ed25519/workflows/Node%20CI/badge.svg) [![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

[Fastest](#speed) 8KB JS implementation of [ed25519](https://en.wikipedia.org/wiki/EdDSA),
[RFC8032](https://tools.ietf.org/html/rfc8032) and [ZIP215](https://zips.z.cash/zip-0215)
compliant EdDSA signature scheme.

The library does not use dependencies and is as minimal as possible. [noble-curves](https://github.com/paulmillr/noble-curves) is even faster drop-in replacement for noble-ed25519 with more features such as [ristretto255](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448), X25519 and curve25519.

Check out [the online demo](https://paulmillr.com/noble/). See [micro-ed25519-hdkey](https://github.com/paulmillr/ed25519-hdkey) if you need SLIP-0010/BIP32 HDKey implementation using the library.

### This library belongs to _noble_ crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies, one small file
- Easily auditable TypeScript/JS code
- Supported in all major browsers and stable node.js versions
- All releases are signed with PGP keys
- Check out [homepage](https://paulmillr.com/noble/) & all libraries:
  [curves](https://github.com/paulmillr/noble-curves)
  ([secp256k1](https://github.com/paulmillr/noble-secp256k1),
  [ed25519](https://github.com/paulmillr/noble-ed25519)),
  [hashes](https://github.com/paulmillr/noble-hashes)

## Usage

Browser, node.js and [Deno](https://deno.land) are supported, with ECMAScript Modules (ESM).
Use bundlers if you need Common.js.

> npm install @noble/ed25519

```js
import * as ed from '@noble/ed25519';
const privateKey = ed.utils.randomPrivateKey();
const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
const publicKey = ed.getPublicKey(privateKey); // to enable sync methods, see below
const signature = ed.sign(message, privateKey);
const isValid = ed.verify(signature, message, publicKey);
```

## API

There are 3 main methods: `getPublicKey(privateKey)`, `sign(message, privateKey)` and `verify(signature, message, publicKey)`. Utilities have Point abstraction (addition, multiplication) and other
methods.

Only **async methods are available by default** to keep library dependency-free.
To enable sync methods: `import { sha512 } from '@noble/hashes/sha512'; ed.utils.sha512Sync = (...m) => sha512(ed.utils.concatBytes(...m));`

```typescript
type Hex = Uint8Array | string;
function getPublicKey(privateKey: Hex): Uint8Array;
function sign(message: Hex, privateKey: Hex): Uint8Array;
function verify(signature: Hex, message: Hex, publicKey: Hex): boolean;

function getPublicKeyAsync(privateKey: Hex): Promise<Uint8Array>;
function signAsync(message: Hex, privateKey: Hex): Promise<Uint8Array>;
function verifyAsync(signature: Hex, message: Hex, publicKey: Hex): Promise<boolean>;
```

- `getPublicKey()`: generates 32-byte public key from 32-byte private key.
    - Some libraries have 64-byte private keys. Don't worry, those are just priv+pub concatenated.
      Just slice it: `priv64b.slice(0, 32)`
    - Use `Point.fromPrivateKey(privateKey)` if you want `Point` instance instead
    - Use `Point.fromHex(publicKey)` if you want to convert hex / bytes into Point.
      It will use decompression algorithm 5.1.3 of RFC 8032.
    - Use `utils.getExtendedPublicKey` if you need full SHA512 hash of seed
- `sign()`: generates EdDSA signature.
    - `message` - message (not message hash) which would be signed
    - `privateKey` - private key which will sign the hash
- `verify()`: verifies EdDSA signature.
    - Compatible with [ZIP215](https://zips.z.cash/zip-0215):
        - `0 <= sig.R/publicKey < 2**256` (can be `>= curve.P` aka non-canonical encoding)
        - `0 <= sig.s < l`
        - There is no security risk in ZIP behavior, and there is no effect on honestly generated signatures, but it is verify important for consensus-critical applications
        - For additional info about verification strictness, check out [It’s 255:19AM](https://hdevalence.ca/blog/2020-10-04-its-25519am)
    - _Not compatible with RFC8032_ because rfc encorces canonical encoding of R/publicKey
    - `signature` - returned by the `sign` function
    - `message` - message that needs to be verified
    - `publicKey` - e.g. that was generated from `privateKey` by `getPublicKey`

A bunch of useful **utilities** are also exposed:

```typescript
utils.randomPrivateKey(); // cryptographically secure random Uint8Array
utils.sha512Async(message: Uint8Array): Promise<Uint8Array>;
utils.sha512Sync(message: Uint8Array): Promise<Uint8Array>;
utils.mod(number: bigint, modulo = CURVE.P): bigint; // Modular division
utils.invert(number: bigint, modulo = CURVE.P): bigint; // Inverses number over modulo
utils.bytesToHex(bytes: Uint8Array): string; // Convert Uint8Array to hex string
utils.getExtendedPublicKey(privateKey); // returns { head, prefix, scalar, point, pointBytes }
class ExtendedPoint { // Elliptic curve point in Extended (x, y, z, t) coordinates.
  constructor(x: bigint, y: bigint, z: bigint, t: bigint);
  static fromAffine(point: Point): ExtendedPoint;
  static fromHex(hash: string);
  static fromPrivateKey(privateKey: string | Uint8Array);
  toRawBytes(): Uint8Array;
  toHex(): string; // Compact representation of a Point
  isTorsionFree(): boolean; // Multiplies the point by curve order
  toAffine(): Point;
  equals(other: ExtendedPoint): boolean;
  // Note: It does not check whether the `other` point is valid point on curve.
  add(other: ExtendedPoint): ExtendedPoint;
  subtract(other: ExtendedPoint): ExtendedPoint;
  multiply(scalar: bigint): ExtendedPoint;
  multiplyUnsafe(scalar: bigint): ExtendedPoint;
}
// Curve params
ed25519.CURVE.P // 2 ** 255 - 19
ed25519.CURVE.l // 2 ** 252 + 27742317777372353535851937790883648493
ed25519.Point.BASE // new ed25519.Point(Gx, Gy) where
// Gx = 15112221349535400772501151409588531511454012693041857206046113283949847762202n
// Gy = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;

ed25519.utils.TORSION_SUBGROUP; // The 8-torsion subgroup ℰ8.
```

## Security

Noble is production-ready.

1. Version 1 of the library has been audited by an independent security firm cure53: [PDF](https://cure53.de/pentest-report_ed25519.pdf). No vulnerabilities have been found. The current version is a full rewrite of v1, use at your own risk.
2. The library has also been fuzzed by [Guido Vranken's cryptofuzz](https://github.com/guidovranken/cryptofuzz). You can run the fuzzer by yourself to check it.

We're using built-in JS `BigInt`, which is potentially vulnerable to [timing attacks](https://en.wikipedia.org/wiki/Timing_attack) as [per official spec](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt#cryptography). But, _JIT-compiler_ and _Garbage Collector_ make "constant time" extremely hard to achieve in a scripting language. Which means _any other JS library doesn't use constant-time bigints_. Including bn.js or anything else. Even statically typed Rust, a language without GC, [makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security) for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones. Use low-level libraries & languages. Nonetheless we've hardened implementation of ec curve multiplication to be algorithmically constant time.

We however consider infrastructure attacks like rogue NPM modules very important; that's why it's crucial to minimize the amount of 3rd-party dependencies & native bindings. If your app uses 500 dependencies, any dep could get hacked and you'll be downloading malware with every `npm install`. Our goal is to minimize this attack vector.

## Speed

Benchmarks done with Apple M2 on macOS 12 with Node.js 18.

    getPublicKey(utils.randomPrivateKey()) x 8,627 ops/sec @ 115μs/op
    sign x 4,355 ops/sec @ 229μs/op
    verify x 852 ops/sec @ 1ms/op
    verify (no decompression) x 975 ops/sec @ 1ms/op
    Point.fromHex decompression x 13,512 ops/sec @ 74μs/op

Compare to alternative implementations:

    # tweetnacl@1.0.3 (fast)
    getPublicKey x 2,087 ops/sec @ 479μs/op # aka scalarMultBase
    sign x 667 ops/sec @ 1ms/op

    # sodium-native@3.4.1
    # native bindings to libsodium, **node.js-only**
    sign x 82,925 ops/sec @ 12μs/op

## Contributing

1. Clone the repository
2. `npm install` to install build dependencies like TypeScript
3. `npm run build` to compile TypeScript code
4. `npm run test` to run jest on `test/index.ts`

## License

MIT (c) 2019 Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.

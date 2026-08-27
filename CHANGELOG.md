# Changelog for noble-ed25519

## 3.2.0 (2026-08-27)

### Security and correctness

- Hardened `sign()` and `signAsync()` against caller-controlled message mutation. Signing now snapshots the message once, so nonce and challenge derivation always use the same bytes even when a custom SHA-512 provider re-enters the caller or yields asynchronously.
- Made `verify()` and `verifyAsync()` explicitly reject `null` and other non-object options instead of accepting them or failing indirectly during destructuring.
- Standardized validation with the other Noble curve packages: byte, hex, point, scalar, secret-key, and seed failures now use more precise argument names and `TypeError`/`RangeError` categories.
- Added an actionable error when WebCrypto randomness is unavailable, centralized configurable SHA-512 backend validation, and hardened the public `etc.invert()` helper to reject modulus one as well as zero and non-invertible values.

### Implementation and performance

- Refactored byte/hex conversion, concatenation, hash dispatch, modular arithmetic, point operations, and TypeScript compatibility plumbing to align with noble-curves and noble-secp256k1 while reducing runtime and allocation overhead.
- Removed generated `index.js` and `index.d.ts` artifacts from source control; release builds continue to generate the JavaScript and declarations included in the published package.

### Testing and tooling

- Added vendored NIST ACVP Ed25519 KeyGen, KeyVer, SigGen, and SigVer vectors, refreshed RFC 8032 and Wycheproof vectors, and expanded shared point-arithmetic, property, malformed-input, hash-provider, and message-mutation tests.
- Added scheduled cryptographic fuzzing, upgraded the shared test/release workflows, added bundle-size benchmarking, and streamlined the package scripts and development dependencies.
- Updated supported-version documentation and linked the Noble WebAssembly implementation.

## 3.1.0 (2026-04-11)

- **March 2026 self-audit** (all files): no major issues found.
  - Audited for specification compliance and security.
  - Applied minor hardening in several places.
- Fixed all byte-array types for compatibility with both TypeScript 5.6 and TypeScript 5.9+.
  - TypeScript 5.6 uses `Uint8Array`, while TypeScript 5.9+ made it generic as `Uint8Array<ArrayBuffer>`.
  - This previously caused incompatibilities and errors such as `TS2345`.
  - See [TypeScript issue #62240](https://github.com/microsoft/TypeScript/issues/62240) for more context.
- Fixed `sign()` in Firefox WebExtension contexts, closing issue #120.
- Fixed compilation issues on TypeScript 6.
- Improved tree-shaking and reduced bundle sizes.
- Added extensive documentation throughout the package.

## 3.0.1 (2026-03-17)

- Fixed a low-severity issue affecting `verify`.
  - An attacker **with access to the secret key** could produce signatures valid for all messages for that secret key.
  - Impact was low and primarily affected systems relying on non-repudiation.
  - Special thanks to Yituo He ([@HaveYouTall](https://github.com/HaveYouTall)) and [@sunyxedu](https://github.com/sunyxedu) for reporting the issue.
- Sped up operations by roughly 1.5× using new modular arithmetic based on HAC 14.47 and HAC 14.50.
  - Contributed by [@georg95](https://github.com/georg95) in [pull request #117](https://github.com/paulmillr/noble-ed25519/pull/117).
  - Key generation: 10,594 ops/sec at 94μs/op → 14,610 ops/sec at 68μs/op.
  - Signing: 5,267 ops/sec at 189μs/op → 7,225 ops/sec at 138μs/op.
  - Verification: 1,203 ops/sec at 830μs/op → 1,972 ops/sec at 506μs/op.

## 3.0.0 (2025-08-25)

### Version 3 brings the package closer to noble-curves version 2

- Most methods now expect `Uint8Array`; hex string inputs are prohibited.
- Added `keygen` and `keygenAsync`.
- Node.js 20.19 is now the minimum required version.
- Made various small type and `Point` class changes.
- Moved hash configuration to the `hashes` object:

```js
// Before
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
ed.etc.sha512Async = (...m: Uint8Array[]) => Promise.resolve(sha512(ed.etc.concatBytes(...m)));

// After
ed.hashes.sha512 = sha512;
ed.hashes.sha512Async = (m: Uint8Array) => Promise.resolve(sha512(m));
```

### New contributors

- [@steveluscher](https://github.com/steveluscher) made their first contribution in [pull request #110](https://github.com/paulmillr/noble-ed25519/pull/110).

## 2.3.0 (2025-06-11)

- Rewrote the code in preparation for version 3.
- Removed non-erasable TypeScript syntax, allowing `.ts` code to run natively in Node.js.
- Made `Point` assert validity before encoding.
- Froze `Point` instances on creation.
- Added CI attestation for standalone build files.
- Raised the TypeScript target from ES2020 to ES2022.

## 2.2.3 (2025-01-20)

- Reverted the requirement for `crypto.subtle` introduced in 2.2.0, ensuring synchronous environments work correctly without it and closing issue #108.
- The JSR package was published from commit `a2d948402a95bfcbd51cb97b70749814d67daf78`, which failed to publish on npm.

## 2.2.2 (2025-01-02)

- Improved documentation for public methods, enabling better generated documentation on JSR.

## 2.2.1 (2025-01-02)

- Republished 2.2.0 to JSR without the [`slow-types` option](https://jsr.io/docs/about-slow-types).

## 2.2.0 (2025-01-02)

### Changes

- Improved hex and byte conversion.
- Improved types by using the `isolatedDeclarations` option.

### New contributors

- [@ChALkeR](https://github.com/ChALkeR) made their first contribution in [pull request #105](https://github.com/paulmillr/noble-ed25519/pull/105).

## 2.1.0 (2024-03-24)

- Released one year after 2.0.0, following a deliberately infrequent update schedule for easier auditability.
- Added a `{ zip215: false }` option to `verify` to force FIPS verification behavior.
- Made `verify` return `false` rather than throw direct errors in more cases.
- Added an optional `zip215: boolean` argument to `Point.fromHex`.
- Fixed `Point#toAffine` conversion of zero points.
- Improved the `Uint8Array` check to work in extension contexts.
- Prohibited objects in `signAsync`; they were previously mangled into `Uint8Array` values and could produce incorrect signatures for object-based messages.

### New contributors

- [@quentinadam](https://github.com/quentinadam) made their first contribution in [pull request #82](https://github.com/paulmillr/noble-ed25519/pull/82).
- [@mahnunchik](https://github.com/mahnunchik) made their first contribution in [pull request #95](https://github.com/paulmillr/noble-ed25519/pull/95).
- [@sangaman](https://github.com/sangaman) made their first contribution in [pull request #97](https://github.com/paulmillr/noble-ed25519/pull/97).
- [@LeJamon](https://github.com/LeJamon) made their first contribution in [pull request #99](https://github.com/paulmillr/noble-ed25519/pull/99).

## 2.0.0 (2023-03-24)

Version 2 improves security and reduces the attack surface. The library was reduced fourfold to just over 300 lines and less than 4 KB.

Some features moved to [noble-curves](https://github.com/paulmillr/noble-curves), a safer and faster drop-in replacement with the same API. Switch to noble-curves if you need:

- X25519, Curve25519, or `getSharedSecret`.
- Ristretto255 or `RistrettoPoint`.
- `utils.precompute()` for non-base points.
- Environments without bigint literal support.
- CommonJS support.
- Node.js 18 and older without a shim.

Other migration changes:

- Methods are synchronous by default; use `getPublicKeyAsync`, `signAsync`, and `verifyAsync` for asynchronous versions.
- `bigint` is no longer accepted by `getPublicKey`, `sign`, or `verify`, because Ed25519 is little-endian and accepting it can cause bugs.
- `Point` using two-dimensional coordinates was changed to `ExtendedPoint` using extended coordinates.
- `Signature` was removed; use raw bytes or hex instead.
- `utils` was split into `utils`, matching noble-curves, and `etc`, which contains `sha512Sync` and related helpers.
- See [pull request #76](https://github.com/paulmillr/noble-ed25519/pull/76).

## 1.7.5 (2025-04-16)

- Avoided bigint literals to support limited environments.

## 1.7.4 (2025-04-14)

- Improved the `Uint8Array` check, which previously allowed invalid inputs. Thanks to [@chalker](https://github.com/chalker) for the report.
- Switched `ExtendedPoint` addition and doubling to complete formulas already used by version 2 for better security.

## 1.7.3 (2023-02-07)

- Avoided bigint literals for compatibility with limited engines.

## 1.7.2 (2023-02-04)

- Fixed an `isTorsionFree` bug.
- Improved constant-time behavior.

## 1.7.1 (2022-09-11)

- Added React Native compatibility.
- Removed bigint exponentiation operators to support limited parsers.

## 1.7.0 (2022-08-26)

- Added synchronous methods:

```ts
import { sha512 } from '@noble/hashes/sha512';

ed.utils.sha512Sync = (...m) => sha512(ed.utils.concatBytes(...m));
const { getPublicKey, sign, verify, getExtendedPublicKey } = ed.sync;
getPublicKey(privKey);
```

## 1.6.1 (2022-07-03)

- Fixed the Skypack build by [@Gozala](https://github.com/Gozala) in [pull request #66](https://github.com/paulmillr/noble-ed25519/pull/66).
- Fixed test and CI failures by [@Gozala](https://github.com/Gozala) in [pull request #65](https://github.com/paulmillr/noble-ed25519/pull/65).

## 1.6.0 (2022-02-14)

- Published the first audited version of the library. [Cure53](https://cure53.de) completed the audit; its PDF is available in the repository.
- Made `verify()` ZIP215-compliant and removed possible malleability from its `s` check.
- Added `Point#isTorsionFree()`.
- Added a `RistrettoPoint` class and removed the corresponding methods from `ExtendedPoint`.
- Improved the `ExtendedPoint` equality check.
- Added `utils.hashToPrivateScalar` and `utils.invert`.
- Disallowed invalid `invZ` values in `ExtendedPoint#toAffine`.
- Updated the Deno SHA-512 dependency.
- Improved performance by 10–15%.

## 1.5.3 (2022-01-28)

- Made `verify()` compatible with [ZIP215](https://zips.z.cash/zip-0215) by adjusting its rules.
- Changed `CURVE.l` to represent the curve order instead of `CURVE.n`.
- Fixed the sign in the definition of `CURVE.n`, contributed by [@dsernst](https://github.com/dsernst) in [pull request #49](https://github.com/paulmillr/noble-ed25519/pull/49).

## 1.5.2 (2022-01-27)

- Fixed `getSharedSecret()` so it is commutative.
- Changed `Point#toX25519` to return a little-endian `Uint8Array` instead of a bigint.

## 1.5.1 (2022-01-18)

- Fixed mutation of Node.js `Buffer` input in issue #45.
  - This happened because `Buffer.slice()` is mutable while `Uint8Array.slice()` is not.

## 1.5.0 (2022-01-18)

- Added support for RFC 7748 X25519.
- Made `getSharedSecret` accept Ed25519 keys.
- Added `curve25519.scalarMult` and `curve25519.scalarMultBase` for Curve25519 keys.

### New contributors

- [@dsernst](https://github.com/dsernst) made their first contribution in [pull request #44](https://github.com/paulmillr/noble-ed25519/pull/44).

## 1.4.0 (2022-01-06)

- **Important:** Removed the `string` hex return type from public methods; they now always return `Uint8Array`.
- Improved hex parsing security.
- Removed the legacy `SignResult` class that duplicated `Signature`.

## 1.3.3 (2021-12-31)

- Avoided bigint literals to support limited ECMAScript parsers.

## 1.3.2 (2021-12-30)

- Fixed ESM and Deno compatibility.

## 1.3.1 (2021-12-30)

- Added ECMAScript module support.
- Removed the TypeScript dependency on `@types/dom`.
- Improved hex parsing security.
- Disallowed private scalars larger than the curve order in `Point#multiply`.

## 1.3.0 (2021-11-05)

- Moved the npm package from `noble-ed25519` to `@noble/ed25519`. Namespaces cannot be claimed by other publishers, so the `@noble` scope authenticates the package.
- Improved Rollup builds.

## 1.2.6 (2021-09-29)

- Made small improvements to `utils`.

## 1.2.5 (2021-06-26)

- Added service-worker support in browsers. Thanks to [@Mrtenz](https://github.com/Mrtenz).

## 1.2.4 (2021-06-18)

- Added a `browser` field to `package.json`.

## 1.2.3 (2021-05-29)

- Fixed a compatibility issue with older TypeScript versions and added a Rollup-based single-file release build.

## 1.2.2 (2021-05-28)

- Rejected invalid private keys longer than 32 bytes. Thanks to [@guidovranken](https://github.com/guidovranken).

## 1.2.1 (2021-04-26)

- Simplified and hardened Ristretto encoding internals, improved validation errors, and reduced generated code.

## 1.2.0 (2021-04-26)

- Hardened signature scalar validation and cofactored verification, added `Point.fromPrivateKey`, sped up point decompression, and rewrote the Ristretto implementation.

## 1.0.3 (2021-01-31)

- Made byte equality checks constant-time and improved signature APIs and types.

## 1.0.2 (2020-10-01)

- Fixed `Point.negate`.

## 1.0.1 (2020-06-22)

- Added Deno support.

## 1.0.0 (2020-05-15)

- First stable release.

## 0.1.0 (2020-05-15)

- Initial release

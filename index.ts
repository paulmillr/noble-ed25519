/*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
/**
 * 5KB JS implementation of ed25519 EdDSA signatures.
 * Targets RFC8032, FIPS 186-5, and ZIP215 behavior.
 * @module
 * @example
 * ```js
import * as ed from '@noble/ed25519';
(async () => {
  const secretKey = ed.utils.randomSecretKey();
  const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
  const pubKey = await ed.getPublicKeyAsync(secretKey); // Sync methods are also present
  const signature = await ed.signAsync(message, secretKey);
  const isValid = await ed.verifyAsync(signature, message, pubKey);
})();
```
 */
/**
 * Curve params. edwards25519 uses the RFC equation `-x² + y² = 1 + dx²y²`.
 * The stored `a` literal below is `p - 1`, i.e. the field-element encoding of RFC `a = -1`.
 * * P = `2n**255n - 19n` // field over which calculations are done
 * * N = `2n**252n + 27742317777372353535851937790883648493n` // prime-order subgroup order
 * * h = 8 // cofactor
 * * a = `Fp.create(BigInt(-1))` // equation param, stored here as `p - 1`
 * * d = -121665/121666 a.k.a. `Fp.neg(121665 * Fp.inv(121666))` // equation param
 * * Gx, Gy are coordinates of Generator / base point
 *
 * Mirror noble-curves: Point.CURVE() exposes shared params, but callers must not be able to mutate
 * that shared view and desynchronize it from the arithmetic constants captured below.
 */
const ed25519_CURVE: EdwardsOpts = Object.freeze({
  p: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn,
  n: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
  h: 8n,
  a: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffecn,
  d: 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n,
  Gx: 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an,
  Gy: 0x6666666666666666666666666666666666666666666666666666666666666658n,
});
const { p: P, n: N, Gx, Gy, a: _a, d: _d, h } = ed25519_CURVE;
const L = 32; // shared 32-byte encoded width for Ed25519 points, scalars, signatures, and keys
/** Alias to Uint8Array. */
export type Bytes = Uint8Array;
/**
 * Bytes API type helpers for old + new TypeScript.
 *
 * TS 5.6 has `Uint8Array`, while TS 5.9+ made it generic `Uint8Array<ArrayBuffer>`.
 * We can't use specific return type, because TS 5.6 will error.
 * We can't use generic return type, because most TS 5.9 software will expect specific type.
 *
 * Maps typed-array input leaves to broad forms.
 * These are compatibility adapters, not ownership guarantees.
 *
 * - `TArg` keeps byte inputs broad.
 * - `TRet` marks byte outputs for TS 5.6 and TS 5.9+ compatibility.
 */
export type TypedArg<T> = T extends BigInt64Array
  ? BigInt64Array
  : T extends BigUint64Array
    ? BigUint64Array
    : T extends Float32Array
      ? Float32Array
      : T extends Float64Array
        ? Float64Array
        : T extends Int16Array
          ? Int16Array
          : T extends Int32Array
            ? Int32Array
            : T extends Int8Array
              ? Int8Array
              : T extends Uint16Array
                ? Uint16Array
                : T extends Uint32Array
                  ? Uint32Array
                  : T extends Uint8ClampedArray
                    ? Uint8ClampedArray
                    : T extends Uint8Array
                      ? Uint8Array
                      : never;
/** Maps typed-array output leaves to narrow TS-compatible forms. */
export type TypedRet<T> = T extends BigInt64Array
  ? ReturnType<typeof BigInt64Array.of>
  : T extends BigUint64Array
    ? ReturnType<typeof BigUint64Array.of>
    : T extends Float32Array
      ? ReturnType<typeof Float32Array.of>
      : T extends Float64Array
        ? ReturnType<typeof Float64Array.of>
        : T extends Int16Array
          ? ReturnType<typeof Int16Array.of>
          : T extends Int32Array
            ? ReturnType<typeof Int32Array.of>
            : T extends Int8Array
              ? ReturnType<typeof Int8Array.of>
              : T extends Uint16Array
                ? ReturnType<typeof Uint16Array.of>
                : T extends Uint32Array
                  ? ReturnType<typeof Uint32Array.of>
                  : T extends Uint8ClampedArray
                    ? ReturnType<typeof Uint8ClampedArray.of>
                    : T extends Uint8Array
                      ? ReturnType<typeof Uint8Array.of>
                      : never;
/** Recursively adapts byte-carrying API input types. See {@link TypedArg}. */
export type TArg<T> =
  | T
  | ([TypedArg<T>] extends [never]
      ? T extends (...args: infer A) => infer R
        ? ((...args: { [K in keyof A]: TRet<A[K]> }) => TArg<R>) & {
            [K in keyof T]: T[K] extends (...args: any) => any ? T[K] : TArg<T[K]>;
          }
        : T extends [infer A, ...infer R]
          ? [TArg<A>, ...{ [K in keyof R]: TArg<R[K]> }]
          : T extends readonly [infer A, ...infer R]
            ? readonly [TArg<A>, ...{ [K in keyof R]: TArg<R[K]> }]
            : T extends (infer A)[]
              ? TArg<A>[]
              : T extends readonly (infer A)[]
                ? readonly TArg<A>[]
                : T extends Promise<infer A>
                  ? Promise<TArg<A>>
                  : T extends object
                    ? { [K in keyof T]: TArg<T[K]> }
                    : T
      : TypedArg<T>);
/** Recursively adapts byte-carrying API output types. See {@link TypedArg}. */
export type TRet<T> = T extends unknown
  ? T &
      ([TypedRet<T>] extends [never]
        ? T extends (...args: infer A) => infer R
          ? ((...args: { [K in keyof A]: TArg<A[K]> }) => TRet<R>) & {
              [K in keyof T]: T[K] extends (...args: any) => any ? T[K] : TRet<T[K]>;
            }
          : T extends [infer A, ...infer R]
            ? [TRet<A>, ...{ [K in keyof R]: TRet<R[K]> }]
            : T extends readonly [infer A, ...infer R]
              ? readonly [TRet<A>, ...{ [K in keyof R]: TRet<R[K]> }]
              : T extends (infer A)[]
                ? TRet<A>[]
                : T extends readonly (infer A)[]
                  ? readonly TRet<A>[]
                  : T extends Promise<infer A>
                    ? Promise<TRet<A>>
                    : T extends object
                      ? { [K in keyof T]: TRet<T[K]> }
                      : T
        : TypedRet<T>)
  : never;
/** Edwards elliptic curve options. */
export type EdwardsOpts = Readonly<{
  /** Prime field modulus. */
  p: bigint;
  /** Group order. */
  n: bigint;
  /** Curve cofactor. */
  h: bigint;
  /** Edwards curve parameter `a`. */
  a: bigint;
  /** Edwards curve parameter `d`. */
  d: bigint;
  /** Generator x coordinate. */
  Gx: bigint;
  /** Generator y coordinate. */
  Gy: bigint;
}>;

// Helpers and Precomputes sections are reused between libraries

// ## Helpers
// ----------
// @ts-ignore
const captureTrace = (...args: Parameters<typeof Error.captureStackTrace>): void => {
  if ('captureStackTrace' in Error && typeof Error.captureStackTrace === 'function') {
    Error.captureStackTrace(...args);
  }
};
const err = (message = ''): never => {
  const e = new Error(message);
  captureTrace(e, err);
  throw e;
};
const isBig = (n: unknown): n is bigint => typeof n === 'bigint'; // is big integer
const isStr = (s: unknown): s is string => typeof s === 'string'; // is string
// Plain `instanceof Uint8Array` is too strict for some Buffer / proxy / cross-realm cases. The
// fallback still requires a real ArrayBuffer view so plain JSON-deserialized `{ constructor: ... }`
// spoofing is rejected, and `BYTES_PER_ELEMENT === 1` keeps the fallback on byte-oriented views.
const isBytes = (a: unknown): a is Bytes =>
  a instanceof Uint8Array ||
  (ArrayBuffer.isView(a) &&
    a.constructor.name === 'Uint8Array' &&
    'BYTES_PER_ELEMENT' in a &&
    a.BYTES_PER_ELEMENT === 1);
/**
 * Asserts something is Bytes, optionally enforces exact length,
 * and returns the same reference.
 */
const abytes = (value: TArg<Bytes>, length?: number, title: string = ''): TRet<Bytes> => {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== undefined;
  if (!bytes || (needsLen && len !== length)) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : '';
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    const msg = prefix + 'expected Uint8Array' + ofLen + ', got ' + got;
    throw bytes ? new RangeError(msg) : new TypeError(msg);
  }
  return value as TRet<Bytes>;
};
/** create Uint8Array */
const u8n = (len: number): TRet<Bytes> => new Uint8Array(len) as TRet<Bytes>;
// Clone helper used before in-place byte edits such as sign-bit clearing or endian reversal.
const u8fr = (buf: ArrayLike<number>): TRet<Bytes> => Uint8Array.from(buf) as TRet<Bytes>;
// Left-pad hex to a caller-chosen width. Width enforcement/truncation policy stays with callers.
const padh = (n: number | bigint, pad: number) => n.toString(16).padStart(pad, '0');
// Lowercase hex serializer.
const bytesToHex = (b: TArg<Bytes>): string =>
  Array.from(abytes(b))
    .map((e) => padh(e, 2))
    .join('');
const C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 } as const; // ASCII characters
const _ch = (ch: number): number | undefined => {
  if (ch >= C._0 && ch <= C._9) return ch - C._0; // '2' => 50-48
  if (ch >= C.A && ch <= C.F) return ch - (C.A - 10); // 'B' => 66-(65-10)
  if (ch >= C.a && ch <= C.f) return ch - (C.a - 10); // 'b' => 98-(97-10)
  return;
};
// Accepts both uppercase and lowercase hex; all parse failures intentionally collapse to `hex invalid`.
const hexToBytes = (hex: string): TRet<Bytes> => {
  const e = 'hex invalid';
  if (!isStr(hex)) return err(e);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2) return err(e);
  const array = u8n(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    // treat each char as ASCII
    const n1 = _ch(hex.charCodeAt(hi)); // parse first char, multiply it by 16
    const n2 = _ch(hex.charCodeAt(hi + 1)); // parse second char
    if (n1 === undefined || n2 === undefined) return err(e);
    array[ai] = n1 * 16 + n2; // example: 'A9' => 10*16 + 9
  }
  return array;
};
declare const globalThis: Record<string, any> | undefined; // Typescript symbol present in browsers
const cr = () => globalThis?.crypto; // Optional WebCrypto lookup; sync code still handles absence.
// Async-path capability helper for WebCrypto-backed APIs.
const subtle = () => cr()?.subtle ?? err('crypto.subtle must be defined, consider polyfill');
// prettier-ignore
const concatBytes = (...arrs: TArg<Bytes[]>): TRet<Bytes> => {
  // Argument order is transcript-significant for hash/signature callers, and input validation here
  // intentionally reuses `abytes(...)` without making defensive copies of the source chunks.
  let len = 0;
  for (const a of arrs) len += abytes(a).length;
  const r = u8n(len); // create u8a of summed length
  let pad = 0; // walk through each array,
  arrs.forEach(a => { r.set(a, pad); pad += a.length; }); // ensure they have proper type
  return r as TRet<Bytes>;
};
/** WebCrypto OS-level CSPRNG (random number generator). Absence still fails later via `cr()`. */
const randomBytes = (len: number = L): TRet<Bytes> => {
  const c = cr();
  return c.getRandomValues(u8n(len)) as TRet<Bytes>;
};
const big = BigInt;
/** Inclusive-lower, exclusive-upper bigint range assertion. */
const assertRange = (
  n: bigint,
  min: bigint,
  max: bigint,
  msg = 'bad number: out of range'
): bigint => {
  if (!isBig(n)) throw new TypeError(msg);
  if (min <= n && n < max) return n;
  throw new RangeError(msg);
};
/** Canonical modular reduction into `[0, b)`. */
const M = (a: bigint, b: bigint = P): bigint => {
  const r = a % b;
  return r >= 0n ? r : b + r;
};
// Low-255-bit mask used by the `2^255 - 19` fast reduction in `modP(...)`.
const P_MASK = (1n << 255n) - 1n;
// Fast reduction for the special prime `2^255 - 19`. This path assumes nonnegative inputs; the
// generic fallback would simply be `M(num, P)`.
const modP = (num: bigint): bigint => {
  // return M(num, P);
  if (num < 0n) err('negative coordinate');
  let r = (num >> 255n) * 19n + (num & P_MASK);
  r = (r >> 255n) * 19n + (r & P_MASK);
  return r % P;
};
// Reduce modulo the subgroup order stored in implementation constant `N` (RFC 8032's `L`).
const modN = (a: bigint) => M(a, N);
/** Modular inversion using Euclidean GCD (non-CT) instead of the RFC's `x^(p-2)` formulation.
 * This still sits on secret-dependent paths like point normalization during keygen/signing. */
// prettier-ignore
const invert = (num: bigint, md: bigint): bigint => {
  if (num === 0n || md <= 0n) err('no inverse n=' + num + ' mod=' + md);
  let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {
    const q = b / a, r = b % a;
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === 1n ? M(x, md) : err('no inverse'); // b is gcd at this point
};
// Dynamic lookup keeps sync/async hash providers configurable at runtime. Both exported slots are
// caller-owned and may be unset; wrapper helpers use this lookup first and then enforce the digest
// contract instead of trusting provider output.
const callHash = (name: string) => {
  // @ts-ignore
  const fn = hashes[name];
  if (typeof fn !== 'function') err('hashes.' + name + ' not set');
  return fn;
};
// Both provider slots are configurable API surface and may return arbitrary values, so callers must
// enforce the promised 64-byte SHA-512 digest contract here instead of trusting provider output.
const checkDigest = (value: TArg<Bytes>): TRet<Bytes> => abytes(value, 64, 'digest');
/**
 * SHA-512 helper used by the synchronous API.
 * @param msg - Message bytes to hash.
 * @returns 64-byte SHA-512 digest.
 * @example
 * Hash message bytes after wiring the synchronous SHA-512 implementation.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 * import { sha512 } from '@noble/hashes/sha2.js';
 *
 * ed.hashes.sha512 = sha512;
 * const digest = ed.hash(new Uint8Array([1, 2, 3]));
 * ```
 */
// Public helper validates the message boundary explicitly; the configured provider is still looked
// up dynamically and its output is checked with `checkDigest(...)`.
const hash = (msg: TArg<Bytes>): TRet<Bytes> =>
  checkDigest(callHash('sha512')(abytes(msg, undefined, 'message')));
// Runtime class guard: this is `instanceof Point`, so cross-realm / duplicate-bundle Point objects
// are rejected even if they are structurally identical.
const apoint = (p: unknown) => (p instanceof Point ? p : err('Point expected'));
/** Point in 2d xy affine coordinates. */
export type AffinePoint = {
  /** Affine x coordinate. */
  x: bigint;
  /** Affine y coordinate. */
  y: bigint;
};
// ## End of Helpers
// -----------------

// Exclusive upper bound `2^256` used by 32-byte decode/serialization range checks.
const B256 = 2n ** 256n;
/**
 * Point in XYZT extended coordinates.
 * @param X - X coordinate.
 * @param Y - Y coordinate.
 * @param Z - Projective Z coordinate.
 * @param T - Cached cross-product term.
 * @example
 * Do point arithmetic with the built-in base point and encode the result as hex.
 *
 * ```ts
 * const hex = Point.BASE.double().toHex();
 * ```
 */
class Point {
  static BASE: Point;
  static ZERO: Point;
  readonly X: bigint;
  readonly Y: bigint;
  readonly Z: bigint;
  readonly T: bigint;
  // Constructor only bounds-checks and freezes XYZT coordinates; it does not prove the point is
  // on-curve or that T matches X*Y/Z.
  constructor(X: bigint, Y: bigint, Z: bigint, T: bigint) {
    const max = B256;
    this.X = assertRange(X, 0n, max);
    this.Y = assertRange(Y, 0n, max);
    this.Z = assertRange(Z, 1n, max);
    this.T = assertRange(T, 0n, max);
    Object.freeze(this);
  }
  static CURVE(): EdwardsOpts {
    return ed25519_CURVE;
  }
  static fromAffine(p: AffinePoint): Point {
    return new Point(p.x, p.y, 1n, modP(p.x * p.y));
  }
  /** RFC8032 5.1.3: Bytes to Point. */
  static fromBytes(hex: TArg<Bytes>, zip215 = false): Point {
    const d = _d;
    // Copy array to not mess it up.
    const normed = u8fr(abytes(hex, L));
    // adjust first LE byte = last BE byte
    const lastByte = hex[31];
    normed[31] = lastByte & ~0x80;
    const y = bytesToNumberLE(normed);
    // After clearing the sign bit, parsed `y` is always < 2^255. ZIP-215 still accepts the full
    // post-mask range here, while strict RFC8032 decoding further requires `y < p`.
    const max = zip215 ? B256 : P;
    assertRange(y, 0n, max);

    const y2 = modP(y * y); // y²
    const u = M(y2 - 1n); // u=y²-1
    const v = modP(d * y2 + 1n); // v=dy²+1
    let { isValid, value: x } = uvRatio(u, v); // (uv³)(uv⁷)^(p-5)/8; square root
    if (!isValid) err('bad point: y not sqrt'); // not square root: bad point
    const isXOdd = (x & 1n) === 1n; // adjust sign of x coordinate
    const isLastByteOdd = (lastByte & 0x80) !== 0; // x_0, last bit
    // ZIP-215-compatible decoding keeps the x=0 / sign-bit=1 encoding accepted; strict RFC 8032
    // rejects it, but the vendored ZIP-215 compliance vectors include this form in A/R bytes.
    if (!zip215 && x === 0n && isLastByteOdd) err('bad point: x==0, isLastByteOdd'); // x=0, x_0=1
    if (isLastByteOdd !== isXOdd) x = M(-x);
    return new Point(x, y, 1n, modP(x * y)); // Z=1, T=xy
  }
  static fromHex(hex: string, zip215?: boolean): Point {
    return Point.fromBytes(hexToBytes(hex), zip215);
  }
  get x(): bigint {
    return this.toAffine().x;
  }
  get y(): bigint {
    return this.toAffine().y;
  }
  /** Checks if the point is valid and on-curve. */
  assertValidity(): this {
    const a = _a;
    const d = _d;
    const p = this;
    // Intentional stricter-than-on-curve policy: reject ZERO by default because many protocols
    // require a non-zero point, and silently accepting identity points is a common caller mistake.
    if (p.is0()) return err('bad point: ZERO'); // TODO: optimize, with vars below?
    // Equation in affine coordinates: ax² + y² = 1 + dx²y²
    // Equation in projective coordinates (X/Z, Y/Z, Z):  (aX² + Y²)Z² = Z⁴ + dX²Y²
    const { X, Y, Z, T } = p;
    const X2 = modP(X * X); // X²
    const Y2 = modP(Y * Y); // Y²
    const Z2 = modP(Z * Z); // Z²
    const Z4 = modP(Z2 * Z2); // Z⁴
    const aX2 = modP(X2 * a); // aX²
    const left = modP(Z2 * (aX2 + Y2)); // (aX² + Y²)Z²
    const right = M(Z4 + modP(d * modP(X2 * Y2))); // Z⁴ + dX²Y²
    if (left !== right) return err('bad point: equation left != right (1)');
    // In Extended coordinates we also have T, which is x*y=T/Z: check X*Y == Z*T
    const XY = modP(X * Y);
    const ZT = modP(Z * T);
    if (XY !== ZT) return err('bad point: equation left != right (2)');
    return this;
  }
  /** Equality check: compare points P&Q. */
  equals(other: Point): boolean {
    const { X: X1, Y: Y1, Z: Z1 } = this;
    const { X: X2, Y: Y2, Z: Z2 } = apoint(other); // checks class equality
    const X1Z2 = modP(X1 * Z2);
    const X2Z1 = modP(X2 * Z1);
    const Y1Z2 = modP(Y1 * Z2);
    const Y2Z1 = modP(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }
  is0(): boolean {
    return this.equals(I);
  }
  /** Flip point over y coordinate. */
  negate(): Point {
    return new Point(M(-this.X), this.Y, this.Z, M(-this.T));
  }
  /** Point doubling. Complete formula. Cost: `4M + 4S + 1*a + 6add + 1*2`. */
  double(): Point {
    const { X: X1, Y: Y1, Z: Z1 } = this;
    const a = _a;
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
    const A = modP(X1 * X1);
    const B = modP(Y1 * Y1);
    const C = modP(2n * Z1 * Z1);
    const D = modP(a * A);
    const x1y1 = M(X1 + Y1);
    const E = M(modP(x1y1 * x1y1) - A - B);
    const G = M(D + B);
    const F = M(G - C);
    const H = M(D - B);
    const X3 = modP(E * F);
    const Y3 = modP(G * H);
    const T3 = modP(E * H);
    const Z3 = modP(F * G);
    return new Point(X3, Y3, Z3, T3);
  }
  /** Point addition. Complete formula. Cost: `8M + 1*k + 8add + 1*2`. */
  add(other: Point): Point {
    const { X: X1, Y: Y1, Z: Z1, T: T1 } = this;
    const { X: X2, Y: Y2, Z: Z2, T: T2 } = apoint(other); // doesn't check if other on-curve
    const a = _a;
    const d = _d;
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
    const A = modP(X1 * X2);
    const B = modP(Y1 * Y2);
    const C = modP(modP(T1 * d) * T2);
    const D = modP(Z1 * Z2);
    const E = M(modP(M(X1 + Y1) * M(X2 + Y2)) - A - B);
    const F = M(D - C);
    const G = M(D + C);
    const H = M(B - modP(a * A));
    const X3 = modP(E * F);
    const Y3 = modP(G * H);
    const T3 = modP(E * H);
    const Z3 = modP(F * G);
    return new Point(X3, Y3, Z3, T3);
  }
  subtract(other: Point): Point {
    return this.add(apoint(other).negate());
  }
  /**
   * Point-by-scalar multiplication. Safe mode requires `1 <= n < CURVE.n`.
   * Unsafe mode additionally permits `n = 0` and returns the identity point for that case.
   * Uses {@link wNAF} for base point.
   * Uses fake point to mitigate side-channel leakage.
   * @param n - scalar by which point is multiplied
   * @param safe - safe mode guards against timing attacks; unsafe mode is faster
   */
  multiply(n: bigint, safe = true): Point {
    // Mirror noble-curves: unsafe mode still validates scalar range first, but intentionally keeps
    // `n = 0` as the one extra accepted case used by verification-style callers.
    if (!safe && n === 0n) return I;
    assertRange(n, 1n, N);
    if (!safe && this.is0()) return I;
    if (n === 1n) return this;
    if (this.equals(G)) return wNAF(n).p;
    // init result point & fake point
    let p = I;
    let f = G;
    for (let d: Point = this; n > 0n; d = d.double(), n >>= 1n) {
      // if bit is present, add to point
      // if not present, add to fake, for timing safety
      if (n & 1n) p = p.add(d);
      else if (safe) f = f.add(d);
    }
    return p;
  }
  multiplyUnsafe(scalar: bigint): Point {
    return this.multiply(scalar, false);
  }
  /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
  toAffine(): AffinePoint {
    const { X, Y, Z } = this;
    // Fast-path only for the identity point; all other inputs still go through inversion.
    if (this.equals(I)) return { x: 0n, y: 1n };
    const iz = invert(Z, P);
    // (Z * Z^-1) must be 1, otherwise bad math
    if (modP(Z * iz) !== 1n) err('invalid inverse');
    // x = X*Z^-1; y = Y*Z^-1
    const x = modP(X * iz);
    const y = modP(Y * iz);
    return { x, y };
  }
  toBytes(): TRet<Bytes> {
    const { x, y } = this.toAffine();
    const b = numTo32bLE(y);
    // store sign in first LE byte
    b[31] |= x & 1n ? 0x80 : 0;
    return b;
  }
  toHex(): string {
    return bytesToHex(this.toBytes());
  }

  clearCofactor(): Point {
    return this.multiply(big(h), false);
  }
  isSmallOrder(): boolean {
    return this.clearCofactor().is0();
  }
  isTorsionFree(): boolean {
    // Multiply by big number N. We can't `mul(N)` because of checks. Instead, we `mul(N/2)*2+1`
    let p = this.multiply(N / 2n, false).double();
    if (N % 2n) p = p.add(this);
    return p.is0();
  }
}
/** Generator / base point */
const G: Point = new Point(Gx, Gy, 1n, M(Gx * Gy));
/** Identity / zero point */
const I: Point = new Point(0n, 1n, 1n, 0n);
// Static aliases
Point.BASE = G;
Point.ZERO = I;

const numTo32bLE = (num: bigint): TRet<Bytes> =>
  hexToBytes(padh(assertRange(num, 0n, B256), 64)).reverse() as TRet<Bytes>;
// Caller-enforced width: some sites require 32-byte RFC encodings, while others intentionally feed
// wider SHA-512 output chunks through the same little-endian parser.
const bytesToNumberLE = (b: TArg<Bytes>): bigint =>
  big('0x' + bytesToHex(u8fr(abytes(b)).reverse()));

const pow2 = (x: bigint, power: bigint): bigint => {
  // pow2(x, 4) == x^(2^4)
  // Negative `power` values are not rejected here and currently leave `x` unchanged.
  let r = x;
  while (power-- > 0n) {
    r = modP(r * r);
  }
  return r;
};

// prettier-ignore
const pow_2_252_3 = (x: bigint) => {                    // x^(2^252-3) unrolled util for square root
  const x2 = modP(x * x);                               // x^2,       bits 1
  const b2 = modP(x2 * x);                              // x^3,       bits 11
  const b4 = modP(pow2(b2, 2n) * b2);                   // x^(2^4-1), bits 1111
  const b5 = modP(pow2(b4, 1n) * x);                    // x^(2^5-1), bits 11111
  const b10 = modP(pow2(b5, 5n) * b5);                  // x^(2^10-1)
  const b20 = modP(pow2(b10, 10n) * b10);               // x^(2^20-1)
  const b40 = modP(pow2(b20, 20n) * b20);               // x^(2^40-1)
  const b80 = modP(pow2(b40, 40n) * b40);               // x^(2^80-1)
  const b160 = modP(pow2(b80, 80n) * b80);              // x^(2^160-1)
  const b240 = modP(pow2(b160, 80n) * b80);             // x^(2^240-1)
  const b250 = modP(pow2(b240, 10n) * b10);             // x^(2^250-1)
  const pow_p_5_8 = modP(pow2(b250, 2n) * x);           // x^((p-5)/8), used by RFC8032 point decode
  return { pow_p_5_8, b2 };
}
const RM1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0n; // 2^((p-1)/4) = sqrt(-1)
// RFC8032 §5.1.3 square-root helper for point decompression. `value` is only meaningful when
// `isValid` is true; callers are also expected to pass canonical field elements with non-zero `v`.
// prettier-ignore
const uvRatio = (u: bigint, v: bigint): { isValid: boolean, value: bigint } => {
  const v3 = modP(v * modP(v * v));                              // v³
  const v7 = modP(modP(v3 * v3) * v);                            // v⁷
  const pow = pow_2_252_3(modP(u * v7)).pow_p_5_8;            // (uv⁷)^(p-5)/8
  let x = modP(u * modP(v3 * pow));                              // (uv³)(uv⁷)^(p-5)/8
  const vx2 = modP(v * modP(x * x));                             // vx²
  const root1 = x;                                      // First root candidate
  const root2 = modP(x * RM1);                             // Second root candidate; RM1 is √-1
  const useRoot1 = vx2 === u;                           // If vx² = u (mod p), x is a square root
  const useRoot2 = vx2 === M(-u);                       // If vx² = -u, set x <-- x * 2^((p-1)/4)
  const noRoot = vx2 === M(-u * RM1);                   // There is no valid root, vx² = -u√-1
  if (useRoot1) x = root1;
  if (useRoot2 || noRoot) x = root2;                    // We return root2 anyway, for const-time
  if ((M(x) & 1n) === 1n) x = M(-x);                    // edIsNegative
  return { isValid: useRoot1 || useRoot2, value: x };
}
// Implementation `N` is the subgroup order; `L` is only the shared 32-byte encoded width constant.
// Reduce any little-endian byte string modulo the subgroup order; the `hash` name reflects the
// common caller shape, not an input restriction.
const modL_LE = (hash: TArg<Bytes>): bigint => modN(bytesToNumberLE(hash)); // modulo L; but little-endian
// Both sync and async SHA-512 slots are exported/configurable; use `callHash(...)` for both so
// missing async overrides fail explicitly, then validate the returned digest type/length.
const sha512a = (...m: TArg<Bytes[]>): Promise<TRet<Bytes>> =>
  Promise.resolve(callHash('sha512Async')(concatBytes(...m))).then(checkDigest);
const sha512s = (...m: TArg<Bytes[]>): TRet<Bytes> =>
  checkDigest(callHash('sha512')(concatBytes(...m)));
type ExtK = { head: Bytes; prefix: Bytes; scalar: bigint; point: Point; pointBytes: Bytes };

// RFC8032 5.1.5. Split the 64-byte hashed seed into the clamped scalar half and nonce prefix.
const hash2extK = (hashed: TArg<Bytes>): TRet<ExtK> => {
  // slice creates a copy, unlike subarray
  const copy = u8fr(hashed);
  const head = copy.slice(0, 32);
  head[0] &= 248; // Clamp bits: 0b1111_1000
  head[31] &= 127; // 0b0111_1111
  head[31] |= 64; // 0b0100_0000
  const prefix = copy.slice(32, 64); // secret key "prefix"
  // RFC words this as `[s]B`; reducing the clamped little-endian scalar modulo `N` is equivalent
  // for base-point multiplication because `G` already has subgroup order `N`.
  const scalar = modL_LE(head);
  const point = G.multiply(scalar); // public key point
  const pointBytes = point.toBytes(); // point serialized to Uint8Array
  return { head, prefix, scalar, point, pointBytes } as TRet<ExtK>;
};

// RFC8032 5.1.5; getPublicKey async, sync. Hash priv key and extract point.
const getExtendedPublicKeyAsync = (secretKey: TArg<Bytes>): Promise<TRet<ExtK>> =>
  sha512a(abytes(secretKey, L)).then(hash2extK);
const getExtendedPublicKey = (secretKey: TArg<Bytes>): TRet<ExtK> =>
  hash2extK(sha512s(abytes(secretKey, L)));
/**
 * Creates a 32-byte Ed25519 public key from the RFC 8032 32-byte secret-key seed. Async.
 * @param secretKey - 32-byte RFC 8032 secret-key seed, not a 64-byte expanded secret key.
 * @returns 32-byte public key.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Derive the public key bytes for a newly generated signer secret.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 *
 * const secretKey = ed.utils.randomSecretKey();
 * const publicKey = await ed.getPublicKeyAsync(secretKey);
 * ```
 */
const getPublicKeyAsync = (secretKey: TArg<Bytes>): Promise<TRet<Bytes>> =>
  getExtendedPublicKeyAsync(secretKey).then((p) => p.pointBytes as TRet<Bytes>);
/**
 * Creates a 32-byte Ed25519 public key from the RFC 8032 32-byte secret-key seed.
 * To use, set `hashes.sha512` first.
 * @param priv - 32-byte RFC 8032 secret-key seed, not a 64-byte expanded secret key.
 * @returns 32-byte public key.
 * @throws If synchronous SHA-512 has not been configured in `hashes`. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Derive the public key entirely through the synchronous API.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 * import { sha512 } from '@noble/hashes/sha2.js';
 *
 * ed.hashes.sha512 = sha512;
 * const secretKey = ed.utils.randomSecretKey();
 * const publicKey = ed.getPublicKey(secretKey);
 * ```
 */
const getPublicKey = (priv: TArg<Bytes>): TRet<Bytes> => getExtendedPublicKey(priv).pointBytes;
type Finishable<T> = {
  // Shared between sync/async sign() and verify(): hash `hashable` with SHA-512, then hand the
  // resulting 64-byte digest to `finish(...)`.
  hashable: Bytes;
  finish: (hashed: Bytes) => T;
};
const hashFinishA = <T>(res: TArg<Finishable<T>>): Promise<TRet<T>> =>
  sha512a((res as Finishable<T>).hashable).then((res as Finishable<T>).finish) as Promise<TRet<T>>;
const hashFinishS = <T>(res: TArg<Finishable<T>>): TRet<T> =>
  (res as Finishable<T>).finish(sha512s((res as Finishable<T>).hashable)) as TRet<T>;
// Code, shared between sync & async sign
const _sign = (
  e: TArg<{ pointBytes: Bytes; scalar: bigint }>,
  rBytes: TArg<Bytes>,
  msg: TArg<Bytes>
): TRet<Finishable<Bytes>> => {
  const { pointBytes: P, scalar: s } = e;
  const r = modL_LE(rBytes); // r was created outside, reduce it modulo L
  // RFC 8032 5.1.6 allows r mod L = 0, and SUPERCOP ref10 accepts the resulting identity-point
  // signature.
  // We intentionally keep the safe multiply() rejection here so a miswired all-zero SHA-512 provider
  // fails loudly instead of silently producing a degenerate signature.
  const R = G.multiply(r).toBytes(); // R = [r]B
  const hashable = concatBytes(R, P, msg); // dom2(F, C) || R || A || PH(M)
  const finish = (hashed: TArg<Bytes>): TRet<Bytes> => {
    // k = SHA512(dom2(F, C) || R || A || PH(M))
    const S = modN(r + modL_LE(hashed) * s); // S = (r + k * s) mod L; 0 <= s < l
    return abytes(concatBytes(R, numTo32bLE(S)), 64); // 64-byte sig: 32-byte encoded R point || 32-byte LE(S)
  };
  return { hashable, finish } as TRet<Finishable<Bytes>>;
};
/**
 * Signs message using secret key. Async.
 * Follows RFC8032 5.1.6.
 * @param message - Message bytes to sign.
 * @param secretKey - 32-byte RFC 8032 secret-key seed, not a 64-byte expanded secret key.
 * @returns 64-byte Ed25519 signature.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Sign an arbitrary message with a fresh Ed25519 secret key.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 *
 * const secretKey = ed.utils.randomSecretKey();
 * const message = new Uint8Array([1, 2, 3]);
 * const signature = await ed.signAsync(message, secretKey);
 * ```
 */
const signAsync = async (message: TArg<Bytes>, secretKey: TArg<Bytes>): Promise<TRet<Bytes>> => {
  const m = abytes(message);
  const e = await getExtendedPublicKeyAsync(secretKey);
  const rBytes = await sha512a(e.prefix, m); // r = SHA512(dom2(F, C) || prefix || PH(M))
  return hashFinishA(_sign(e, rBytes, m)); // gen R, k, S, then 64-byte signature
};
/**
 * Signs message using secret key. To use, set `hashes.sha512` first.
 * Follows RFC8032 5.1.6.
 * @param message - Message bytes to sign.
 * @param secretKey - 32-byte RFC 8032 secret-key seed, not a 64-byte expanded secret key.
 * @returns 64-byte Ed25519 signature.
 * @throws If synchronous SHA-512 has not been configured in `hashes`. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Use the sync API when you've wired a SHA-512 implementation yourself.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 * import { sha512 } from '@noble/hashes/sha2.js';
 *
 * ed.hashes.sha512 = sha512;
 * const secretKey = ed.utils.randomSecretKey();
 * const signature = ed.sign(new Uint8Array([1, 2, 3]), secretKey);
 * ```
 */
const sign = (message: TArg<Bytes>, secretKey: TArg<Bytes>): TRet<Bytes> => {
  const m = abytes(message);
  const e = getExtendedPublicKey(secretKey);
  const rBytes = sha512s(e.prefix, m); // r = SHA512(dom2(F, C) || prefix || PH(M))
  return hashFinishS(_sign(e, rBytes, m)); // gen R, k, S, then 64-byte signature
};
/**
 * Verification options. zip215: true (default) follows ZIP215 spec. false would follow RFC8032.
 *
 * Any message with pubkey from `ED25519_TORSION_SUBGROUP` would be valid in sigs under ZIP215.
 */
export type EdDSAVerifyOpts = {
  /** Whether to use ZIP215 verification semantics instead of the library's stricter branch. */
  zip215?: boolean;
};
// Exported defaults favor ZIP-215 interoperability semantics; callers must opt into the stricter
// branch with `{ zip215: false }`.
const defaultVerifyOpts: EdDSAVerifyOpts = { zip215: true };
const _verify = (
  sig: TArg<Bytes>,
  msg: TArg<Bytes>,
  publicKey: TArg<Bytes>,
  options: TArg<EdDSAVerifyOpts> = defaultVerifyOpts
): TRet<Finishable<boolean>> => {
  sig = abytes(sig, 64); // Signature hex str/Bytes, must be 64 bytes
  msg = abytes(msg); // Message hex str/Bytes
  publicKey = abytes(publicKey, L);
  // zip215=false keeps the library's stricter branch, which still canonicalizes `R` / `A` before
  // hashing and rejects small-order public keys earlier than pure RFC8032 text would require.
  // Preserve the exported ZIP-215 default for `{}` / `{ zip215: undefined }`, not just omitted opts.
  const { zip215 = true } = options;

  const r = sig.subarray(0, L);
  const s = bytesToNumberLE(sig.subarray(L, L * 2)); // Decode second half as an integer S;
  let A: Point, R: Point, SB: Point;
  let hashable: Bytes = Uint8Array.of();
  let finished = false;
  try {
    // zip215=true is good for consensus-critical apps. =false follows RFC8032 / NIST186-5.
    // zip215=true:  0 <= y < MASK (2^256 for ed25519)
    // zip215=false: 0 <= y < P (2^255-19 for ed25519)
    A = Point.fromBytes(publicKey, zip215);
    R = Point.fromBytes(r, zip215);
    SB = G.multiply(s, false); // 0 <= s < l is done inside
    // ZIP-215 accepts noncanonical / unreduced point encodings, so the challenge hash must use the
    // exact signature/public-key bytes rather than canonicalized re-encodings of the decoded points.
    hashable = concatBytes(r, publicKey, msg); // dom2(F, C) || R || A || PH(M)
    finished = true;
  } catch (error) {}
  const finish = (hashed: TArg<Bytes>): boolean => {
    if (!finished) return false;
    // Policy: strict mode intentionally rejects all small-order public keys, even though the raw RFC
    // equation text is looser here. This matches libsodium and avoids weak / ambiguous verification
    // outcomes where unusual low-order public keys can make distinct key/signature combinations verify.
    if (!zip215 && A.isSmallOrder()) return false;

    // k = SHA512(dom2(F, C) || R || A || PH(M))
    const k = modL_LE(hashed);
    const RkA = R.add(A.multiply(k, false));
    // Extended group equation
    // [8][S]B = [8]R + [8][k]A'
    return RkA.subtract(SB).clearCofactor().is0();
  };
  return { hashable, finish } as TRet<Finishable<boolean>>;
};

/**
 * Verifies a signature on message and public key. Async.
 * The implementation is based on RFC8032 5.1.7, but default opts use ZIP-215 semantics; pass
 * `{ zip215: false }` for the library's stricter branch.
 * @param signature - 64-byte signature.
 * @param message - Signed message bytes.
 * @param publicKey - 32-byte public key.
 * @param opts - Verification options. Defaults to ZIP-215 semantics. See {@link EdDSAVerifyOpts}.
 * @returns `true` when the signature is valid.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Verify the signature against the same message and derived public key.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 *
 * const secretKey = ed.utils.randomSecretKey();
 * const message = new Uint8Array([1, 2, 3]);
 * const publicKey = await ed.getPublicKeyAsync(secretKey);
 * const signature = await ed.signAsync(message, secretKey);
 * const isValid = await ed.verifyAsync(signature, message, publicKey);
 * ```
 */
const verifyAsync = async (
  signature: TArg<Bytes>,
  message: TArg<Bytes>,
  publicKey: TArg<Bytes>,
  opts: TArg<EdDSAVerifyOpts> = defaultVerifyOpts
): Promise<boolean> => hashFinishA(_verify(signature, message, publicKey, opts));
/**
 * Verifies a signature on message and public key using the synchronous hash path.
 * The implementation is based on RFC8032 5.1.7, but default opts use ZIP-215 semantics; pass
 * `{ zip215: false }` for the library's stricter branch.
 * @param signature - 64-byte signature.
 * @param message - Signed message bytes.
 * @param publicKey - 32-byte public key.
 * @param opts - Verification options. Defaults to ZIP-215 semantics. See {@link EdDSAVerifyOpts}.
 * @returns `true` when the signature is valid.
 * @throws If synchronous SHA-512 has not been configured in `hashes`. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Verify a signature entirely through the synchronous API.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 * import { sha512 } from '@noble/hashes/sha2.js';
 *
 * ed.hashes.sha512 = sha512;
 * const secretKey = ed.utils.randomSecretKey();
 * const message = new Uint8Array([1, 2, 3]);
 * const publicKey = ed.getPublicKey(secretKey);
 * const signature = ed.sign(message, secretKey);
 * const isValid = ed.verify(signature, message, publicKey);
 * ```
 */
const verify = (
  signature: TArg<Bytes>,
  message: TArg<Bytes>,
  publicKey: TArg<Bytes>,
  opts: TArg<EdDSAVerifyOpts> = defaultVerifyOpts
): boolean => hashFinishS(_verify(signature, message, publicKey, opts));

/**
 * Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves.
 * Exposes the same low-level field-default `mod` reducer and non-CT `invert` helper used
 * internally.
 * @example
 * Convert bytes to a hex string with the low-level helper namespace.
 *
 * ```ts
 * const hex = etc.bytesToHex(new Uint8Array([1, 2, 3]));
 * ```
 */
const etc: {
  bytesToHex: (bytes: TArg<Bytes>) => string;
  hexToBytes: (hex: string) => TRet<Bytes>;
  concatBytes: (...arrs: TArg<Bytes[]>) => TRet<Bytes>;
  mod: typeof M;
  invert: typeof invert;
  randomBytes: (len?: number) => TRet<Bytes>;
} = /* @__PURE__ */ Object.freeze({
  bytesToHex,
  hexToBytes,
  concatBytes,
  mod: M as typeof M,
  invert: invert as typeof invert,
  randomBytes,
});
/**
 * Hash implementations used by the synchronous API plus the default async WebCrypto provider.
 * Both slots are configurable API surface; wrapper helpers revalidate that providers still return
 * 64-byte SHA-512 digests.
 * @example
 * Provide a SHA-512 implementation before calling synchronous helpers.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 * import { sha512 } from '@noble/hashes/sha2.js';
 *
 * ed.hashes.sha512 = sha512;
 * const { publicKey } = ed.keygen();
 * ```
 */
const hashes = {
  sha512Async: async (message: TArg<Bytes>): Promise<TRet<Bytes>> => {
    const s = subtle();
    const m = concatBytes(message);
    return u8n(await s.digest('SHA-512', m.buffer)) as TRet<Bytes>;
  },
  sha512: undefined as undefined | ((message: TArg<Bytes>) => TRet<Bytes>),
};

// Returns the final 32-byte Ed25519 secret-key seed verbatim, generating fresh random bytes only
// when omitted.
const randomSecretKey = (seed?: TArg<Bytes>): TRet<Bytes> => {
  seed = seed === undefined ? randomBytes(L) : seed;
  return abytes(seed, L);
};

type KeysSecPub = { secretKey: Bytes; publicKey: Bytes };
/**
 * Generates a secret/public keypair.
 * @param seed - Optional 32-byte Ed25519 secret-key seed, returned verbatim as `secretKey`.
 * @returns Keypair with `secretKey` and `publicKey`.
 * @throws If synchronous SHA-512 has not been configured in `hashes`. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Generate a new keypair through the synchronous API after wiring SHA-512.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 * import { sha512 } from '@noble/hashes/sha2.js';
 *
 * ed.hashes.sha512 = sha512;
 * const { secretKey, publicKey } = ed.keygen();
 * ```
 */
const keygen = (seed?: TArg<Bytes>): TRet<KeysSecPub> => {
  const secretKey = randomSecretKey(seed);
  const publicKey = getPublicKey(secretKey);
  return { secretKey, publicKey } as TRet<KeysSecPub>;
};
/**
 * Generates a secret/public keypair asynchronously.
 * @param seed - Optional 32-byte Ed25519 secret-key seed, returned verbatim as `secretKey`.
 * @returns Keypair with `secretKey` and `publicKey`.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Generate a new keypair through the asynchronous WebCrypto-backed path.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 *
 * const { secretKey, publicKey } = await ed.keygenAsync();
 * ```
 */
const keygenAsync = async (seed?: TArg<Bytes>): Promise<TRet<KeysSecPub>> => {
  const secretKey = randomSecretKey(seed);
  const publicKey = await getPublicKeyAsync(secretKey);
  return { secretKey, publicKey } as TRet<KeysSecPub>;
};

/**
 * Ed25519-specific key utilities.
 * `utils.getExtendedPublicKey*` expose secret-derived internals (`head`, `prefix`, `scalar`, and
 * point objects), not just public-key bytes.
 * @example
 * Generate a new Ed25519 secret key and derive the matching public key.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 *
 * const secretKey = ed.utils.randomSecretKey();
 * const publicKey = await ed.getPublicKeyAsync(secretKey);
 * ```
 */
const utils: {
  getExtendedPublicKeyAsync: typeof getExtendedPublicKeyAsync;
  getExtendedPublicKey: typeof getExtendedPublicKey;
  randomSecretKey: typeof randomSecretKey;
} = /* @__PURE__ */ Object.freeze({
  getExtendedPublicKeyAsync: getExtendedPublicKeyAsync as typeof getExtendedPublicKeyAsync,
  getExtendedPublicKey: getExtendedPublicKey as typeof getExtendedPublicKey,
  randomSecretKey: randomSecretKey as typeof randomSecretKey,
});

// ## Precomputes
// --------------

const W = 8; // W is window size
const scalarBits = 256;
const pwindows = Math.ceil(scalarBits / W) + 1; // 33 for W=8, NOT 32 - see wNAF loop
const pwindowSize = 2 ** (W - 1); // 128 for W=8
// Layout is grouped by window: each block stores the positive multiples `1*base .. 128*base` for
// that window, and the extra `+1` window in `pwindows` absorbs carries from signed-digit recoding.
const precompute = () => {
  const points: Point[] = [];
  let p = G;
  let b = p;
  for (let w = 0; w < pwindows; w++) {
    b = p;
    points.push(b);
    for (let i = 1; i < pwindowSize; i++) {
      b = b.add(p);
      points.push(b);
    } // i=1, bc we skip 0
    p = b.double();
  }
  return points;
};
let Gpows: Point[] | undefined = undefined; // shared process-wide cache of base-point precomputes
// Branch-based negate helper used for JS/JIT mitigation symmetry, not a strict constant-time claim.
const ctneg = (cnd: boolean, p: TArg<Point>) => {
  const n = (p as Point).negate();
  return cnd ? n : (p as Point);
};

/**
 * Precomputes give 12x faster getPublicKey(), 10x sign(), 2x verify() by
 * caching multiples of G (base point). Cache is stored in 32MB of RAM.
 * Any time `G.multiply` is done, precomputes are used.
 * Not used for getSharedSecret, which instead multiplies random pubkey `P.multiply`.
 *
 * w-ary non-adjacent form (wNAF) precomputation method is 10% slower than windowed method,
 * but takes 2x less RAM. RAM reduction is possible by utilizing `.subtract`.
 * Returns the real accumulator `p` plus a fake accumulator `f`; callers only care about `p`, while
 * `f` exists to keep similar work in zero-digit branches as a JS/JIT side-channel mitigation.
 *
 * !! Precomputes can be disabled by commenting-out call of the wNAF() inside Point#multiply().
 */
const wNAF = (n: bigint): TRet<{ p: Point; f: Point }> => {
  const comp = Gpows || (Gpows = precompute());
  let p = I;
  let f = G; // f must be G, or could become I in the end
  const pow_2_w = 2 ** W; // 256 for W=8
  const maxNum = pow_2_w; // 256 for W=8
  const mask = big(pow_2_w - 1); // 255 for W=8 == mask 0b11111111
  const shiftBy = big(W); // 8 for W=8
  for (let w = 0; w < pwindows; w++) {
    let wbits = Number(n & mask); // extract W bits.
    n >>= shiftBy; // shift number by W bits.
    // We use negative indexes to reduce size of precomputed table by 2x.
    // Instead of needing precomputes 0..256, we only calculate them for 0..128.
    // If an index > 128 is found, we do (256-index) - where 256 is next window.
    // Naive: index +127 => 127, +224 => 224
    // Optimized: index +127 => 127, +224 => 256-32
    if (wbits > pwindowSize) {
      wbits -= maxNum;
      n += 1n;
    }
    const off = w * pwindowSize;
    const offF = off; // offsets, evaluate both
    const offP = off + Math.abs(wbits) - 1;
    const isEven = w % 2 !== 0; // conditions, evaluate both
    const isNeg = wbits < 0;
    if (wbits === 0) {
      // off == I: can't add it. Adding random offF instead.
      f = f.add(ctneg(isEven, comp[offF])); // bits are 0: add garbage to fake point
    } else {
      p = p.add(ctneg(isNeg, comp[offP])); // bits are 1: add to result point
    }
  }
  if (n !== 0n) err('invalid wnaf');
  return { p, f } as TRet<{ p: Point; f: Point }>; // callers only need `p`; `f` is kept for zero-digit mitigation symmetry
};

// !! Remove the export to easily use in REPL / browser console
export {
  etc,
  getPublicKey,
  getPublicKeyAsync,
  hash,
  hashes,
  keygen,
  keygenAsync,
  Point,
  sign,
  signAsync,
  utils,
  verify,
  verifyAsync
};


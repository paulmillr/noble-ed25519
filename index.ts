/*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
// Thanks DJB https://ed25519.cr.yp.to
// https://tools.ietf.org/html/rfc7748 https://tools.ietf.org/html/rfc8032
// https://en.wikipedia.org/wiki/EdDSA https://ristretto.group
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448

// Uses built-in crypto module from node.js to generate randomness / hmac-sha256.
// In browser the line is automatically removed during build time: uses crypto.subtle instead.
import * as nodeCrypto from 'crypto';

// Be friendly to bad ECMAScript parsers by not using bigint literals like 123n
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _255n = BigInt(255);
const CURVE_ORDER = _2n ** BigInt(252) + BigInt('27742317777372353535851937790883648493');

/**
 * ed25519 is Twisted Edwards curve with equation of
 * ```
 * −x² + y² = 1 − (121665/121666) * x² * y²
 * ```
 */
const CURVE = Object.freeze({
  // Param: a
  a: BigInt(-1),
  // Equal to -121665/121666 over finite field.
  // Negative number is P - number, and division is invert(number, P)
  d: BigInt('37095705934669439343138083508754565189542113879843219016388785533085940283555'),
  // Finite field 𝔽p over which we'll do calculations
  P: _2n ** _255n - BigInt(19),
  // Subgroup order: how many points ed25519 has
  l: CURVE_ORDER, // in rfc8032 it's called l
  n: CURVE_ORDER, // backwards compatibility
  // Cofactor
  h: BigInt(8),
  // Base point (x, y) aka generator point
  Gx: BigInt('15112221349535400772501151409588531511454012693041857206046113283949847762202'),
  Gy: BigInt('46316835694926478169428394003475163141307993866256225615783033603165251855960'),
});

// Cleaner output this way.
export { CURVE };

type Hex = Uint8Array | string;
type PrivKey = Hex | bigint | number;
type PubKey = Hex | Point;
type SigType = Hex | Signature;

const MAX_256B = _2n ** BigInt(256);

// √(-1) aka √(a) aka 2^((p-1)/4)
const SQRT_M1 = BigInt(
  '19681161376707505956807079304988542015446066515923890162744021073123829784752'
);
// √d aka sqrt(-486664)
const SQRT_D = BigInt(
  '6853475219497561581579357271197624642482790079785650197046958215289687604742'
);
// √(ad - 1)
const SQRT_AD_MINUS_ONE = BigInt(
  '25063068953384623474111414158702152701244531502492656460079210482610430750235'
);
// 1 / √(a-d)
const INVSQRT_A_MINUS_D = BigInt(
  '54469307008909316920995813868745141605393597292927456921205312896311721017578'
);
// 1-d²
const ONE_MINUS_D_SQ = BigInt(
  '1159843021668779879193775521855586647937357759715417654439879720876111806838'
);
// (d-1)²
const D_MINUS_ONE_SQ = BigInt(
  '40440834346308536858101042469323190826248399146238708352240133220865137265952'
);

/**
 * Extended Point works in extended coordinates: (x, y, z, t) ∋ (x=x/z, y=y/z, t=xy).
 * Default Point works in affine coordinates: (x, y)
 * https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Extended_coordinates
 */
class ExtendedPoint {
  constructor(readonly x: bigint, readonly y: bigint, readonly z: bigint, readonly t: bigint) {}

  static BASE = new ExtendedPoint(CURVE.Gx, CURVE.Gy, _1n, mod(CURVE.Gx * CURVE.Gy));
  static ZERO = new ExtendedPoint(_0n, _1n, _1n, _0n);
  static fromAffine(p: Point): ExtendedPoint {
    if (!(p instanceof Point)) {
      throw new TypeError('ExtendedPoint#fromAffine: expected Point');
    }
    if (p.equals(Point.ZERO)) return ExtendedPoint.ZERO;
    return new ExtendedPoint(p.x, p.y, _1n, mod(p.x * p.y));
  }
  // Takes a bunch of Jacobian Points but executes only one
  // invert on all of them. invert is very slow operation,
  // so this improves performance massively.
  static toAffineBatch(points: ExtendedPoint[]): Point[] {
    const toInv = invertBatch(points.map((p) => p.z));
    return points.map((p, i) => p.toAffine(toInv[i]));
  }

  static normalizeZ(points: ExtendedPoint[]): ExtendedPoint[] {
    return this.toAffineBatch(points).map(this.fromAffine);
  }

  // Compare one point to another.
  equals(other: ExtendedPoint): boolean {
    assertExtPoint(other);
    const { x: X1, y: Y1, z: Z1 } = this;
    const { x: X2, y: Y2, z: Z2 } = other;
    const X1Z2 = mod(X1 * Z2);
    const X2Z1 = mod(X2 * Z1);
    const Y1Z2 = mod(Y1 * Z2);
    const Y2Z1 = mod(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }

  // Inverses point to one corresponding to (x, -y) in Affine coordinates.
  negate(): ExtendedPoint {
    return new ExtendedPoint(mod(-this.x), this.y, this.z, mod(-this.t));
  }

  // Fast algo for doubling Extended Point when curve's a=-1.
  // http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd
  // Cost: 3M + 4S + 1*a + 7add + 1*2.
  double(): ExtendedPoint {
    const { x: X1, y: Y1, z: Z1 } = this;
    const { a } = CURVE;
    const A = mod(X1 ** _2n);
    const B = mod(Y1 ** _2n);
    const C = mod(_2n * mod(Z1 ** _2n));
    const D = mod(a * A);
    const E = mod(mod((X1 + Y1) ** _2n) - A - B);
    const G = D + B;
    const F = G - C;
    const H = D - B;
    const X3 = mod(E * F);
    const Y3 = mod(G * H);
    const T3 = mod(E * H);
    const Z3 = mod(F * G);
    return new ExtendedPoint(X3, Y3, Z3, T3);
  }

  // Fast algo for adding 2 Extended Points when curve's a=-1.
  // http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-4
  // Cost: 8M + 8add + 2*2.
  // Note: It does not check whether the `other` point is valid.
  add(other: ExtendedPoint) {
    assertExtPoint(other);
    const { x: X1, y: Y1, z: Z1, t: T1 } = this;
    const { x: X2, y: Y2, z: Z2, t: T2 } = other;
    const A = mod((Y1 - X1) * (Y2 + X2));
    const B = mod((Y1 + X1) * (Y2 - X2));
    const F = mod(B - A);
    if (F === _0n) return this.double(); // Same point.
    const C = mod(Z1 * _2n * T2);
    const D = mod(T1 * _2n * Z2);
    const E = D + C;
    const G = B + A;
    const H = D - C;
    const X3 = mod(E * F);
    const Y3 = mod(G * H);
    const T3 = mod(E * H);
    const Z3 = mod(F * G);
    return new ExtendedPoint(X3, Y3, Z3, T3);
  }

  subtract(other: ExtendedPoint): ExtendedPoint {
    return this.add(other.negate());
  }

  private precomputeWindow(W: number): ExtendedPoint[] {
    const windows = 1 + 256 / W;
    const points: ExtendedPoint[] = [];
    let p: ExtendedPoint = this;
    let base = p;
    for (let window = 0; window < windows; window++) {
      base = p;
      points.push(base);
      for (let i = 1; i < 2 ** (W - 1); i++) {
        base = base.add(p);
        points.push(base);
      }
      p = base.double();
    }
    return points;
  }

  private wNAF(n: bigint, affinePoint?: Point): ExtendedPoint {
    if (!affinePoint && this.equals(ExtendedPoint.BASE)) affinePoint = Point.BASE;
    const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
    if (256 % W) {
      throw new Error('Point#wNAF: Invalid precomputation window, must be power of 2');
    }

    let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
    if (!precomputes) {
      precomputes = this.precomputeWindow(W);
      if (affinePoint && W !== 1) {
        precomputes = ExtendedPoint.normalizeZ(precomputes);
        pointPrecomputes.set(affinePoint, precomputes);
      }
    }

    let p = ExtendedPoint.ZERO;
    let f = ExtendedPoint.ZERO;

    const windows = 1 + 256 / W;
    const windowSize = 2 ** (W - 1);
    const mask = BigInt(2 ** W - 1); // Create mask with W ones: 0b1111 for W=4 etc.
    const maxNumber = 2 ** W;
    const shiftBy = BigInt(W);

    for (let window = 0; window < windows; window++) {
      const offset = window * windowSize;
      // Extract W bits.
      let wbits = Number(n & mask);

      // Shift number by W bits.
      n >>= shiftBy;

      // If the bits are bigger than max size, we'll split those.
      // +224 => 256 - 32
      if (wbits > windowSize) {
        wbits -= maxNumber;
        n += _1n;
      }

      // Check if we're onto Zero point.
      // Add random point inside current window to f.
      if (wbits === 0) {
        let pr = precomputes[offset];
        if (window % 2) pr = pr.negate();
        f = f.add(pr);
      } else {
        let cached = precomputes[offset + Math.abs(wbits) - 1];
        if (wbits < 0) cached = cached.negate();
        p = p.add(cached);
      }
    }
    return ExtendedPoint.normalizeZ([p, f])[0];
  }

  // Constant time multiplication.
  // Uses wNAF method. Windowed method may be 10% faster,
  // but takes 2x longer to generate and consumes 2x memory.
  multiply(scalar: number | bigint, affinePoint?: Point): ExtendedPoint {
    return this.wNAF(normalizeScalar(scalar, CURVE.l), affinePoint);
  }

  // Non-constant-time multiplication. Uses double-and-add algorithm.
  // It's faster, but should only be used when you don't care about
  // an exposed private key e.g. sig verification.
  // Allows scalar bigger than curve order, but less than 2^256
  multiplyUnsafe(scalar: number | bigint): ExtendedPoint {
    let n = normalizeScalar(scalar, CURVE.l, false);
    const G = ExtendedPoint.BASE;
    const P0 = ExtendedPoint.ZERO;
    if (n === _0n) return P0;
    if (this.equals(P0) || n === _1n) return this;
    if (this.equals(G)) return this.wNAF(n);
    let p = P0;
    let d: ExtendedPoint = this;
    while (n > _0n) {
      if (n & _1n) p = p.add(d);
      d = d.double();
      n >>= _1n;
    }
    return p;
  }

  isSmallOrder(): boolean {
    return this.multiplyUnsafe(CURVE.h).equals(ExtendedPoint.ZERO);
  }

  isTorsionFree(): boolean {
    return this.multiplyUnsafe(CURVE.l).equals(ExtendedPoint.ZERO);
  }

  // Converts Extended point to default (x, y) coordinates.
  // Can accept precomputed Z^-1 - for example, from invertBatch.
  toAffine(invZ: bigint = invert(this.z)): Point {
    const { x, y, z } = this;
    const ax = mod(x * invZ);
    const ay = mod(y * invZ);
    const zz = mod(z * invZ);
    if (zz !== _1n) throw new Error('invZ was invalid');
    return new Point(ax, ay);
  }

  fromRistrettoBytes() {
    legacyRist();
  }
  toRistrettoBytes() {
    legacyRist();
  }
  fromRistrettoHash() {
    legacyRist();
  }
}

function assertExtPoint(other: unknown) {
  if (!(other instanceof ExtendedPoint)) throw new TypeError('ExtendedPoint expected');
}
function assertRstPoint(other: unknown) {
  if (!(other instanceof RistrettoPoint)) throw new TypeError('RistrettoPoint expected');
}

function legacyRist() {
  throw new Error('Legacy method: switch to RistrettoPoint');
}

/**
 * Each ed25519/ExtendedPoint has 8 different equivalent points. This can be
 * a source of bugs for protocols like ring signatures. Ristretto was created to solve this.
 * Ristretto point operates in X:Y:Z:T extended coordinates like ExtendedPoint,
 * but it should work in its own namespace: do not combine those two.
 * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448
 */
class RistrettoPoint {
  static BASE = new RistrettoPoint(ExtendedPoint.BASE);
  static ZERO = new RistrettoPoint(ExtendedPoint.ZERO);

  // Private property to discourage combining ExtendedPoint + RistrettoPoint
  // Always use Ristretto encoding/decoding instead.
  constructor(private readonly ep: ExtendedPoint) {}

  // Computes Elligator map for Ristretto
  // https://ristretto.group/formulas/elligator.html
  private static calcElligatorRistrettoMap(r0: bigint): ExtendedPoint {
    const { d } = CURVE;
    const r = mod(SQRT_M1 * r0 * r0); // 1
    const Ns = mod((r + _1n) * ONE_MINUS_D_SQ); // 2
    let c = BigInt(-1); // 3
    const D = mod((c - d * r) * mod(r + d)); // 4
    let { isValid: Ns_D_is_sq, value: s } = uvRatio(Ns, D); // 5
    let s_ = mod(s * r0); // 6
    if (!edIsNegative(s_)) s_ = mod(-s_);
    if (!Ns_D_is_sq) s = s_; // 7
    if (!Ns_D_is_sq) c = r; // 8
    const Nt = mod(c * (r - _1n) * D_MINUS_ONE_SQ - D); // 9
    const s2 = s * s;
    const W0 = mod((s + s) * D); // 10
    const W1 = mod(Nt * SQRT_AD_MINUS_ONE); // 11
    const W2 = mod(_1n - s2); // 12
    const W3 = mod(_1n + s2); // 13
    return new ExtendedPoint(mod(W0 * W3), mod(W2 * W1), mod(W1 * W3), mod(W0 * W2));
  }

  /**
   * Takes uniform output of 64-bit hash function like sha512 and converts it to `RistrettoPoint`.
   * The hash-to-group operation applies Elligator twice and adds the results.
   * **Note:** this is one-way map, there is no conversion from point to hash.
   * https://ristretto.group/formulas/elligator.html
   * @param hex 64-bit output of a hash function
   */
  static hashToCurve(hex: Hex): RistrettoPoint {
    hex = ensureBytes(hex, 64);
    const r1 = bytes255ToNumberLE(hex.slice(0, 32));
    const R1 = this.calcElligatorRistrettoMap(r1);
    const r2 = bytes255ToNumberLE(hex.slice(32, 64));
    const R2 = this.calcElligatorRistrettoMap(r2);
    return new RistrettoPoint(R1.add(R2));
  }

  /**
   * Converts ristretto-encoded string to ristretto point.
   * https://ristretto.group/formulas/decoding.html
   * @param hex Ristretto-encoded 32 bytes. Not every 32-byte string is valid ristretto encoding
   */
  static fromHex(hex: Hex): RistrettoPoint {
    hex = ensureBytes(hex, 32);
    const { a, d } = CURVE;
    const emsg = 'RistrettoPoint.fromHex: the hex is not valid encoding of RistrettoPoint';
    const s = bytes255ToNumberLE(hex);
    // 1. Check that s_bytes is the canonical encoding of a field element, or else abort.
    // 3. Check that s is non-negative, or else abort
    if (!equalBytes(numberTo32BytesLE(s), hex) || edIsNegative(s)) throw new Error(emsg);
    const s2 = mod(s * s);
    const u1 = mod(_1n + a * s2); // 4 (a is -1)
    const u2 = mod(_1n - a * s2); // 5
    const u1_2 = mod(u1 * u1);
    const u2_2 = mod(u2 * u2);
    const v = mod(a * d * u1_2 - u2_2); // 6
    const { isValid, value: I } = invertSqrt(mod(v * u2_2)); // 7
    const Dx = mod(I * u2); // 8
    const Dy = mod(I * Dx * v); // 9
    let x = mod((s + s) * Dx); // 10
    if (edIsNegative(x)) x = mod(-x); // 10
    const y = mod(u1 * Dy); // 11
    const t = mod(x * y); // 12
    if (!isValid || edIsNegative(t) || y === _0n) throw new Error(emsg);
    return new RistrettoPoint(new ExtendedPoint(x, y, _1n, t));
  }

  /**
   * Encodes ristretto point to Uint8Array.
   * https://ristretto.group/formulas/encoding.html
   */
  toRawBytes(): Uint8Array {
    let { x, y, z, t } = this.ep;
    const u1 = mod(mod(z + y) * mod(z - y)); // 1
    const u2 = mod(x * y); // 2
    // Square root always exists
    const { value: invsqrt } = invertSqrt(mod(u1 * u2 ** _2n)); // 3
    const D1 = mod(invsqrt * u1); // 4
    const D2 = mod(invsqrt * u2); // 5
    const zInv = mod(D1 * D2 * t); // 6
    let D: bigint; // 7
    if (edIsNegative(t * zInv)) {
      let _x = mod(y * SQRT_M1);
      let _y = mod(x * SQRT_M1);
      x = _x;
      y = _y;
      D = mod(D1 * INVSQRT_A_MINUS_D);
    } else {
      D = D2; // 8
    }
    if (edIsNegative(x * zInv)) y = mod(-y); // 9
    let s = mod((z - y) * D); // 10 (check footer's note, no sqrt(-a))
    if (edIsNegative(s)) s = mod(-s);
    return numberTo32BytesLE(s); // 11
  }

  toHex(): string {
    return bytesToHex(this.toRawBytes());
  }

  toString(): string {
    return this.toHex();
  }

  // Compare one point to another.
  equals(other: RistrettoPoint): boolean {
    assertRstPoint(other);
    const a = this.ep;
    const b = other.ep;
    // (x1 * y2 == y1 * x2) | (y1 * y2 == x1 * x2)
    const one = mod(a.x * b.y) === mod(a.y * b.x);
    const two = mod(a.y * b.y) === mod(a.x * b.x);
    return one || two;
  }

  add(other: RistrettoPoint): RistrettoPoint {
    assertRstPoint(other);
    return new RistrettoPoint(this.ep.add(other.ep));
  }

  subtract(other: RistrettoPoint): RistrettoPoint {
    assertRstPoint(other);
    return new RistrettoPoint(this.ep.subtract(other.ep));
  }

  multiply(scalar: number | bigint): RistrettoPoint {
    return new RistrettoPoint(this.ep.multiply(scalar));
  }

  multiplyUnsafe(scalar: number | bigint): RistrettoPoint {
    return new RistrettoPoint(this.ep.multiplyUnsafe(scalar));
  }
}

// Stores precomputed values for points.
const pointPrecomputes = new WeakMap<Point, ExtendedPoint[]>();

/**
 * Default Point works in affine coordinates: (x, y)
 */
class Point {
  // Base point aka generator
  // public_key = Point.BASE * private_key
  static BASE: Point = new Point(CURVE.Gx, CURVE.Gy);
  // Identity point aka point at infinity
  // point = point + zero_point
  static ZERO: Point = new Point(_0n, _1n);
  // We calculate precomputes for elliptic curve point multiplication
  // using windowed method. This specifies window size and
  // stores precomputed values. Usually only base point would be precomputed.
  _WINDOW_SIZE?: number;

  constructor(readonly x: bigint, readonly y: bigint) {}

  // "Private method", don't use it directly.
  _setWindowSize(windowSize: number) {
    this._WINDOW_SIZE = windowSize;
    pointPrecomputes.delete(this);
  }

  // Converts hash string or Uint8Array to Point.
  // Uses algo from RFC8032 5.1.3.
  static fromHex(hex: Hex, strict = true) {
    const { d, P } = CURVE;
    hex = ensureBytes(hex, 32);
    // 1.  First, interpret the string as an integer in little-endian
    // representation. Bit 255 of this number is the least significant
    // bit of the x-coordinate and denote this value x_0.  The
    // y-coordinate is recovered simply by clearing this bit.  If the
    // resulting value is >= p, decoding fails.
    const normed = hex.slice();
    normed[31] = hex[31] & ~0x80;
    const y = bytesToNumberLE(normed);

    if (strict && y >= P) throw new Error('Expected 0 < hex < P');
    if (!strict && y >= MAX_256B) throw new Error('Expected 0 < hex < 2**256');

    // 2.  To recover the x-coordinate, the curve equation implies
    // x² = (y² - 1) / (d y² + 1) (mod p).  The denominator is always
    // non-zero mod p.  Let u = y² - 1 and v = d y² + 1.
    const y2 = mod(y * y);
    const u = mod(y2 - _1n);
    const v = mod(d * y2 + _1n);
    let { isValid, value: x } = uvRatio(u, v);
    if (!isValid) throw new Error('Point.fromHex: invalid y coordinate');

    // 4.  Finally, use the x_0 bit to select the right square root.  If
    // x = 0, and x_0 = 1, decoding fails.  Otherwise, if x_0 != x mod
    // 2, set x <-- p - x.  Return the decoded point (x,y).
    const isXOdd = (x & _1n) === _1n;
    const isLastByteOdd = (hex[31] & 0x80) !== 0;
    if (isLastByteOdd !== isXOdd) {
      x = mod(-x);
    }
    return new Point(x, y);
  }

  static async fromPrivateKey(privateKey: PrivKey) {
    return (await getExtendedPublicKey(privateKey)).point;
  }

  // There can always be only two x values (x, -x) for any y
  // When compressing point, it's enough to only store its y coordinate
  // and use the last byte to encode sign of x.
  toRawBytes(): Uint8Array {
    const bytes = numberTo32BytesLE(this.y);
    bytes[31] |= this.x & _1n ? 0x80 : 0;
    return bytes;
  }

  // Same as toRawBytes, but returns string.
  toHex(): string {
    return bytesToHex(this.toRawBytes());
  }

  /**
   * Converts to Montgomery; aka x coordinate of curve25519.
   * We don't have fromX25519, because we don't know sign.
   *
   * ```
   * u, v: curve25519 coordinates
   * x, y: ed25519 coordinates
   * (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)
   * (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))
   * ```
   * https://blog.filippo.io/using-ed25519-keys-for-encryption
   * @returns u coordinate of curve25519 point
   */
  toX25519(): Uint8Array {
    const { y } = this;
    const u = mod((_1n + y) * invert(_1n - y));
    return numberTo32BytesLE(u);
  }

  isTorsionFree(): boolean {
    return ExtendedPoint.fromAffine(this).isTorsionFree();
  }

  equals(other: Point): boolean {
    return this.x === other.x && this.y === other.y;
  }

  negate() {
    return new Point(mod(-this.x), this.y);
  }

  add(other: Point) {
    return ExtendedPoint.fromAffine(this).add(ExtendedPoint.fromAffine(other)).toAffine();
  }

  subtract(other: Point) {
    return this.add(other.negate());
  }

  /**
   * Constant time multiplication.
   * @param scalar Big-Endian number
   * @returns new point
   */
  multiply(scalar: number | bigint): Point {
    return ExtendedPoint.fromAffine(this).multiply(scalar, this).toAffine();
  }
}

/**
 * EDDSA signature.
 */
class Signature {
  constructor(readonly r: Point, readonly s: bigint) {
    this.assertValidity();
  }

  static fromHex(hex: Hex) {
    const bytes = ensureBytes(hex, 64);
    const r = Point.fromHex(bytes.slice(0, 32), false);
    const s = bytesToNumberLE(bytes.slice(32, 64));
    return new Signature(r, s);
  }

  assertValidity() {
    const { r, s } = this;
    if (!(r instanceof Point)) throw new Error('Expected Point instance');
    // 0 <= s < l
    normalizeScalar(s, CURVE.l, false);
    return this;
  }

  toRawBytes() {
    const u8 = new Uint8Array(64);
    u8.set(this.r.toRawBytes());
    u8.set(numberTo32BytesLE(this.s), 32);
    return u8;
  }

  toHex() {
    return bytesToHex(this.toRawBytes());
  }
}

export { ExtendedPoint, RistrettoPoint, Point, Signature };

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  if (!arrays.every((a) => a instanceof Uint8Array)) throw new Error('Expected Uint8Array list');
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

// Convert between types
// ---------------------
const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
function bytesToHex(uint8a: Uint8Array): string {
  // pre-caching improves the speed 6x
  if (!(uint8a instanceof Uint8Array)) throw new Error('Uint8Array expected');
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += hexes[uint8a[i]];
  }
  return hex;
}

// Caching slows it down 2-3x
function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
  }
  if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex');
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence');
    array[i] = byte;
  }
  return array;
}

function numberTo32BytesBE(num: bigint) {
  const length = 32;
  const hex = num.toString(16).padStart(length * 2, '0');
  return hexToBytes(hex);
}

function numberTo32BytesLE(num: bigint) {
  return numberTo32BytesBE(num).reverse();
}

// Little-endian check for first LE bit (last BE bit);
function edIsNegative(num: bigint) {
  return (mod(num) & _1n) === _1n;
}

// Little Endian
function bytesToNumberLE(uint8a: Uint8Array): bigint {
  if (!(uint8a instanceof Uint8Array)) throw new Error('Expected Uint8Array');
  return BigInt('0x' + bytesToHex(Uint8Array.from(uint8a).reverse()));
}

function bytes255ToNumberLE(bytes: Uint8Array): bigint {
  return mod(bytesToNumberLE(bytes) & (_2n ** _255n - _1n));
}
// -------------------------

function mod(a: bigint, b: bigint = CURVE.P) {
  const res = a % b;
  return res >= _0n ? res : b + res;
}

// Note: this egcd-based invert is 50% faster than powMod-based one.
// Inverses number over modulo
function invert(number: bigint, modulo: bigint = CURVE.P): bigint {
  if (number === _0n || modulo <= _0n) {
    throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
  }
  // Eucledian GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
  let a = mod(number, modulo);
  let b = modulo;
  // prettier-ignore
  let x = _0n, y = _1n, u = _1n, v = _0n;
  while (a !== _0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    // prettier-ignore
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n) throw new Error('invert: does not exist');
  return mod(x, modulo);
}

/**
 * Takes a list of numbers, efficiently inverts all of them.
 * @param nums list of bigints
 * @param p modulo
 * @returns list of inverted bigints
 * @example
 * invertBatch([1n, 2n, 4n], 21n);
 * // => [1n, 11n, 16n]
 */
function invertBatch(nums: bigint[], p: bigint = CURVE.P): bigint[] {
  const tmp = new Array(nums.length);
  // Walk from first to last, multiply them by each other MOD p
  const lastMultiplied = nums.reduce((acc, num, i) => {
    if (num === _0n) return acc;
    tmp[i] = acc;
    return mod(acc * num, p);
  }, _1n);
  // Invert last element
  const inverted = invert(lastMultiplied, p);
  // Walk from last to first, multiply them by inverted each other MOD p
  nums.reduceRight((acc, num, i) => {
    if (num === _0n) return acc;
    tmp[i] = mod(acc * tmp[i], p);
    return mod(acc * num, p);
  }, inverted);
  return tmp;
}

// Does x ^ (2 ^ power) mod p. pow2(30, 4) == 30 ^ (2 ^ 4)
function pow2(x: bigint, power: bigint): bigint {
  const { P } = CURVE;
  let res = x;
  while (power-- > _0n) {
    res *= res;
    res %= P;
  }
  return res;
}

// Power to (p-5)/8 aka x^(2^252-3)
// Used to calculate y - the square root of y².
// Exponentiates it to very big number.
// We are unwrapping the loop because it's 2x faster.
// (2n**252n-3n).toString(2) would produce bits [250x 1, 0, 1]
// We are multiplying it bit-by-bit
function pow_2_252_3(x: bigint) {
  const { P } = CURVE;
  const _5n = BigInt(5);
  const _10n = BigInt(10);
  const _20n = BigInt(20);
  const _40n = BigInt(40);
  const _80n = BigInt(80);
  const x2 = (x * x) % P;
  const b2 = (x2 * x) % P; // x^3, 11
  const b4 = (pow2(b2, _2n) * b2) % P; // x^15, 1111
  const b5 = (pow2(b4, _1n) * x) % P; // x^31
  const b10 = (pow2(b5, _5n) * b5) % P;
  const b20 = (pow2(b10, _10n) * b10) % P;
  const b40 = (pow2(b20, _20n) * b20) % P;
  const b80 = (pow2(b40, _40n) * b40) % P;
  const b160 = (pow2(b80, _80n) * b80) % P;
  const b240 = (pow2(b160, _80n) * b80) % P;
  const b250 = (pow2(b240, _10n) * b10) % P;
  const pow_p_5_8 = (pow2(b250, _2n) * x) % P;
  // ^ To pow to (p+3)/8, multiply it by x.
  return { pow_p_5_8, b2 };
}

// Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
// Constant-time
// prettier-ignore
function uvRatio(u: bigint, v: bigint): { isValid: boolean, value: bigint } {
  const v3 = mod(v * v * v);                  // v³
  const v7 = mod(v3 * v3 * v);                // v⁷
  const pow = pow_2_252_3(u * v7).pow_p_5_8;
  let x = mod(u * v3 * pow);                  // (uv³)(uv⁷)^(p-5)/8
  const vx2 = mod(v * x * x);                 // vx²
  const root1 = x;                            // First root candidate
  const root2 = mod(x * SQRT_M1);             // Second root candidate
  const useRoot1 = vx2 === u;                 // If vx² = u (mod p), x is a square root
  const useRoot2 = vx2 === mod(-u);           // If vx² = -u, set x <-- x * 2^((p-1)/4)
  const noRoot = vx2 === mod(-u * SQRT_M1);   // There is no valid root, vx² = -u√(-1)
  if (useRoot1) x = root1;
  if (useRoot2 || noRoot) x = root2;          // We return root2 anyway, for const-time
  if (edIsNegative(x)) x = mod(-x);
  return { isValid: useRoot1 || useRoot2, value: x };
}

// Calculates 1/√(number)
function invertSqrt(number: bigint) {
  return uvRatio(_1n, number);
}
// Math end

// Little-endian SHA512 with modulo n
function modlLE(hash: Uint8Array): bigint {
  return mod(bytesToNumberLE(hash), CURVE.l);
}

function equalBytes(b1: Uint8Array, b2: Uint8Array) {
  // We don't care about timing attacks here
  if (b1.length !== b2.length) {
    return false;
  }
  for (let i = 0; i < b1.length; i++) {
    if (b1[i] !== b2[i]) {
      return false;
    }
  }
  return true;
}

function ensureBytes(hex: Hex, expectedLength?: number): Uint8Array {
  // Uint8Array.from() instead of hash.slice() because node.js Buffer
  // is instance of Uint8Array, and its slice() creates **mutable** copy
  const bytes = hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes(hex);
  if (typeof expectedLength === 'number' && bytes.length !== expectedLength)
    throw new Error(`Expected ${expectedLength} bytes`);
  return bytes;
}

/**
 * Checks for num to be in range:
 * For strict == true:  `0 <  num < max`.
 * For strict == false: `0 <= num < max`.
 * Converts non-float safe numbers to bigints.
 */
function normalizeScalar(num: number | bigint, max: bigint, strict = true): bigint {
  if (!max) throw new TypeError('Specify max value');
  if (typeof num === 'number' && Number.isSafeInteger(num)) num = BigInt(num);
  if (typeof num === 'bigint' && num < max) {
    if (strict) {
      if (_0n < num) return num;
    } else {
      if (_0n <= num) return num;
    }
  }
  throw new TypeError('Expected valid scalar: 0 < scalar < max');
}

function adjustBytes25519(bytes: Uint8Array): Uint8Array {
  // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
  // set the three least significant bits of the first byte
  bytes[0] &= 248; // 0b1111_1000
  // and the most significant bit of the last to zero,
  bytes[31] &= 127; // 0b0111_1111
  // set the second most significant bit of the last byte to 1
  bytes[31] |= 64; // 0b0100_0000
  return bytes;
}

function decodeScalar25519(n: Hex): bigint {
  // and, finally, decode as little-endian.
  // This means that the resulting integer is of the form 2 ^ 254 plus eight times a value between 0 and 2 ^ 251 - 1(inclusive).
  return bytesToNumberLE(adjustBytes25519(ensureBytes(n, 32)));
}

function checkPrivateKey(key: PrivKey) {
  // Normalize bigint / number / string to Uint8Array
  key =
    typeof key === 'bigint' || typeof key === 'number'
      ? numberTo32BytesBE(normalizeScalar(key, MAX_256B))
      : ensureBytes(key);
  if (key.length !== 32) throw new Error(`Expected 32 bytes`);
  return key;
}

// Takes 64 bytes
function getKeyFromHash(hashed: Uint8Array) {
  // First 32 bytes of 64b uniformingly random input are taken,
  // clears 3 bits of it to produce a random field element.
  const head = adjustBytes25519(hashed.slice(0, 32));
  // Second 32 bytes is called key prefix (5.1.6)
  const prefix = hashed.slice(32, 64);
  // The actual private scalar
  const scalar = modlLE(head);
  // Point on Edwards curve aka public key
  const point = Point.BASE.multiply(scalar);
  const pointBytes = point.toRawBytes();
  return { head, prefix, scalar, point, pointBytes };
}

type Sha512FnSync = undefined | ((...messages: Uint8Array[]) => Uint8Array);
let _sha512Sync: Sha512FnSync;

// Private convenience method. RFC8032 5.1.5
async function getExtendedPublicKey(key: PrivKey) {
  return getKeyFromHash(await utils.sha512(checkPrivateKey(key)));
}
function getExtendedPublicKeySync(key: PrivKey) {
  return getKeyFromHash(utils.sha512Sync!(checkPrivateKey(key)));
}

//
/**
 * Calculates ed25519 public key.
 * 1. private key is hashed with sha512, then first 32 bytes are taken from the hash
 * 2. 3 least significant bits of the first byte are cleared
 * RFC8032 5.1.5
 */
export async function getPublicKey(privateKey: PrivKey): Promise<Uint8Array> {
  return (await getExtendedPublicKey(privateKey)).pointBytes;
}
function getPublicKeySync(privateKey: PrivKey): Uint8Array {
  return getExtendedPublicKeySync(privateKey).pointBytes;
}

/**
 * Signs message with privateKey.
 * RFC8032 5.1.6
 */
export async function sign(message: Hex, privateKey: Hex): Promise<Uint8Array> {
  message = ensureBytes(message);
  const { prefix, scalar, pointBytes } = await getExtendedPublicKey(privateKey);
  const r = modlLE(await utils.sha512(prefix, message)); // r = hash(prefix + msg)
  const R = Point.BASE.multiply(r); // R = rG
  const k = modlLE(await utils.sha512(R.toRawBytes(), pointBytes, message)); // k = hash(R + P + msg)
  const s = mod(r + k * scalar, CURVE.l); // s = r + kp
  return new Signature(R, s).toRawBytes();
}
function signSync(message: Hex, privateKey: Hex): Uint8Array {
  message = ensureBytes(message);
  const { prefix, scalar, pointBytes } = getExtendedPublicKeySync(privateKey);
  const r = modlLE(utils.sha512Sync!(prefix, message)); // r = hash(prefix + msg)
  const R = Point.BASE.multiply(r); // R = rG
  const k = modlLE(utils.sha512Sync!(R.toRawBytes(), pointBytes, message)); // k = hash(R+P+msg)
  const s = mod(r + k * scalar, CURVE.l); // s = r + kp
  return new Signature(R, s).toRawBytes();
}

// Helper functions because we have async and sync methods.
function prepareVerification(sig: SigType, message: Hex, publicKey: PubKey) {
  message = ensureBytes(message);
  // When hex is passed, we check public key fully.
  // When Point instance is passed, we assume it has already been checked, for performance.
  // If user passes Point/Sig instance, we assume it has been already verified.
  // We don't check its equations for performance. We do check for valid bounds for s though
  // We always check for: a) s bounds. b) hex validity
  if (!(publicKey instanceof Point)) publicKey = Point.fromHex(publicKey, false);
  const { r, s } = sig instanceof Signature ? sig.assertValidity() : Signature.fromHex(sig);
  const SB = ExtendedPoint.BASE.multiplyUnsafe(s);
  return { r, s, SB, pub: publicKey, msg: message };
}

function finishVerification(publicKey: Point, r: Point, SB: ExtendedPoint, hashed: Uint8Array) {
  const k = modlLE(hashed);
  const kA = ExtendedPoint.fromAffine(publicKey).multiplyUnsafe(k);
  const RkA = ExtendedPoint.fromAffine(r).add(kA);
  // [8][S]B = [8]R + [8][k]A'
  return RkA.subtract(SB).multiplyUnsafe(CURVE.h).equals(ExtendedPoint.ZERO);
}

/**
 * Verifies ed25519 signature against message and public key.
 * An extended group equation is checked.
 * RFC8032 5.1.7
 * Compliant with ZIP215:
 * 0 <= sig.R/publicKey < 2**256 (can be >= curve.P)
 * 0 <= sig.s < l
 * Not compliant with RFC8032: it's not possible to comply to both ZIP & RFC at the same time.
 */
export async function verify(sig: SigType, message: Hex, publicKey: PubKey): Promise<boolean> {
  const { r, SB, msg, pub } = prepareVerification(sig, message, publicKey);
  const hashed = await utils.sha512(r.toRawBytes(), pub.toRawBytes(), msg);
  return finishVerification(pub, r, SB, hashed);
}
function verifySync(sig: SigType, message: Hex, publicKey: PubKey): boolean {
  const { r, SB, msg, pub } = prepareVerification(sig, message, publicKey);
  const hashed = utils.sha512Sync!(r.toRawBytes(), pub.toRawBytes(), msg);
  return finishVerification(pub, r, SB, hashed);
}
// if (typeof utils.sha512Sync !== 'function') throw new Error('Expected function')

export const sync = {
  getExtendedPublicKey: getExtendedPublicKeySync,
  getPublicKey: getPublicKeySync,
  sign: signSync,
  verify: verifySync,
};

/**
 * Calculates X25519 DH shared secret from ed25519 private & public keys.
 * Curve25519 used in X25519 consumes private keys as-is, while ed25519 hashes them with sha512.
 * Which means we will need to normalize ed25519 seeds to "hashed repr".
 * @param privateKey ed25519 private key
 * @param publicKey ed25519 public key
 * @returns X25519 shared key
 */
export async function getSharedSecret(privateKey: PrivKey, publicKey: Hex): Promise<Uint8Array> {
  const { head } = await getExtendedPublicKey(privateKey);
  const u = Point.fromHex(publicKey).toX25519();
  return curve25519.scalarMult(head, u);
}

// Enable precomputes. Slows down first publicKey computation by 20ms.
Point.BASE._setWindowSize(8);

// curve25519-related code
// Curve equation: v^2 = u^3 + A*u^2 + u
// https://datatracker.ietf.org/doc/html/rfc7748

// cswap from RFC7748
function cswap(swap: bigint, x_2: bigint, x_3: bigint): [bigint, bigint] {
  const dummy = mod(swap * (x_2 - x_3));
  x_2 = mod(x_2 - dummy);
  x_3 = mod(x_3 + dummy);
  return [x_2, x_3];
}

// x25519 from 4
/**
 *
 * @param pointU u coordinate (x) on Montgomery Curve 25519
 * @param scalar by which the point would be multiplied
 * @returns new Point on Montgomery curve
 */
function montgomeryLadder(pointU: bigint, scalar: bigint): bigint {
  const { P } = CURVE;
  const u = normalizeScalar(pointU, P);
  // Section 5: Implementations MUST accept non-canonical values and process them as
  // if they had been reduced modulo the field prime.
  const k = normalizeScalar(scalar, P);
  // The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519
  const a24 = BigInt(121665);
  const x_1 = u;
  let x_2 = _1n;
  let z_2 = _0n;
  let x_3 = u;
  let z_3 = _1n;
  let swap = _0n;
  let sw: [bigint, bigint];
  for (let t = BigInt(255 - 1); t >= _0n; t--) {
    const k_t = (k >> t) & _1n;
    swap ^= k_t;
    sw = cswap(swap, x_2, x_3);
    x_2 = sw[0];
    x_3 = sw[1];
    sw = cswap(swap, z_2, z_3);
    z_2 = sw[0];
    z_3 = sw[1];
    swap = k_t;

    const A = x_2 + z_2;
    const AA = mod(A * A);
    const B = x_2 - z_2;
    const BB = mod(B * B);
    const E = AA - BB;
    const C = x_3 + z_3;
    const D = x_3 - z_3;
    const DA = mod(D * A);
    const CB = mod(C * B);
    x_3 = mod((DA + CB) ** _2n);
    z_3 = mod(x_1 * (DA - CB) ** _2n);
    x_2 = mod(AA * BB);
    z_2 = mod(E * (AA + mod(a24 * E)));
  }
  sw = cswap(swap, x_2, x_3);
  x_2 = sw[0];
  x_3 = sw[1];
  sw = cswap(swap, z_2, z_3);
  z_2 = sw[0];
  z_3 = sw[1];
  const { pow_p_5_8, b2 } = pow_2_252_3(z_2);
  // x^(p-2) aka x^(2^255-21)
  const xp2 = mod(pow2(pow_p_5_8, BigInt(3)) * b2);
  return mod(x_2 * xp2);
}

function encodeUCoordinate(u: bigint): Uint8Array {
  return numberTo32BytesLE(mod(u, CURVE.P));
}

function decodeUCoordinate(uEnc: Hex): bigint {
  const u = ensureBytes(uEnc, 32);
  // Section 5: When receiving such an array, implementations of X25519
  // MUST mask the most significant bit in the final byte.
  u[31] &= 127; // 0b0111_1111
  return bytesToNumberLE(u);
}

export const curve25519 = {
  BASE_POINT_U: '0900000000000000000000000000000000000000000000000000000000000000',

  // crypto_scalarmult aka getSharedSecret
  scalarMult(privateKey: Hex, publicKey: Hex): Uint8Array {
    const u = decodeUCoordinate(publicKey);
    const p = decodeScalar25519(privateKey);
    const pu = montgomeryLadder(u, p);
    // The result was not contributory
    // https://cr.yp.to/ecdh.html#validate
    if (pu === _0n) throw new Error('Invalid private or public key received');
    return encodeUCoordinate(pu);
  },

  // crypto_scalarmult_base aka getPublicKey
  scalarMultBase(privateKey: Hex): Uint8Array {
    return curve25519.scalarMult(privateKey, curve25519.BASE_POINT_U);
  },
};

// Global symbol available in browsers only. Ensure we do not depend on @types/dom
declare const self: Record<string, any> | undefined;
const crypto: { node?: any; web?: any } = {
  node: nodeCrypto,
  web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
};

export const utils = {
  // The 8-torsion subgroup ℰ8.
  // Those are "buggy" points, if you multiply them by 8, you'll receive Point.ZERO.
  // Ported from curve25519-dalek.
  TORSION_SUBGROUP: [
    '0100000000000000000000000000000000000000000000000000000000000000',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    '0000000000000000000000000000000000000000000000000000000000000080',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
    '0000000000000000000000000000000000000000000000000000000000000000',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  ],
  bytesToHex,
  hexToBytes,
  concatBytes,
  getExtendedPublicKey,
  mod,
  invert,

  /**
   * Can take 40 or more bytes of uniform input e.g. from CSPRNG or KDF
   * and convert them into private scalar, with the modulo bias being neglible.
   * As per FIPS 186 B.4.1.
   * @param hash hash output from sha512, or a similar function
   * @returns valid private scalar
   */
  hashToPrivateScalar: (hash: Hex): bigint => {
    hash = ensureBytes(hash);
    if (hash.length < 40 || hash.length > 1024)
      throw new Error('Expected 40-1024 bytes of private key as per FIPS 186');
    return mod(bytesToNumberLE(hash), CURVE.l - _1n) + _1n;
  },

  randomBytes: (bytesLength: number = 32): Uint8Array => {
    if (crypto.web) {
      return crypto.web.getRandomValues(new Uint8Array(bytesLength));
    } else if (crypto.node) {
      const { randomBytes } = crypto.node;
      return new Uint8Array(randomBytes(bytesLength).buffer);
    } else {
      throw new Error("The environment doesn't have randomBytes function");
    }
  },
  // Note: ed25519 private keys are uniform 32-bit strings. We do not need
  // to check for modulo bias like we do in noble-secp256k1 randomPrivateKey()
  randomPrivateKey: (): Uint8Array => {
    return utils.randomBytes(32);
  },
  sha512: async (...messages: Uint8Array[]): Promise<Uint8Array> => {
    const message = concatBytes(...messages);
    if (crypto.web) {
      const buffer = await crypto.web.subtle.digest('SHA-512', message.buffer);
      return new Uint8Array(buffer);
    } else if (crypto.node) {
      return Uint8Array.from(crypto.node.createHash('sha512').update(message).digest());
    } else {
      throw new Error("The environment doesn't have sha512 function");
    }
  },
  /**
   * We're doing scalar multiplication (used in getPublicKey etc) with precomputed BASE_POINT
   * values. This slows down first getPublicKey() by milliseconds (see Speed section),
   * but allows to speed-up subsequent getPublicKey() calls up to 20x.
   * @param windowSize 2, 4, 8, 16
   */
  precompute(windowSize = 8, point = Point.BASE): Point {
    const cached = point.equals(Point.BASE) ? point : new Point(point.x, point.y);
    cached._setWindowSize(windowSize);
    cached.multiply(_2n);
    return cached;
  },

  sha512Sync: undefined as Sha512FnSync,
};

Object.defineProperties(utils, {
  sha512Sync: {
    configurable: false,
    get() {
      return _sha512Sync;
    },
    set(val) {
      if (!_sha512Sync) _sha512Sync = val;
    },
  },
});

Object.freeze(utils);

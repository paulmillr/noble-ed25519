/*! noble-ed25519 - MIT License (c) Paul Miller (paulmillr.com) */

// Thanks DJB https://ed25519.cr.yp.to
// https://tools.ietf.org/html/rfc8032, https://en.wikipedia.org/wiki/EdDSA
// Includes Ristretto. https://ristretto.group

const CURVE = {
  // Params: a, b
  a: -1n,
  // Equal to -121665/121666 over finite field.
  // Negative number is P - number, and division is invert(number, P)
  d: 37095705934669439343138083508754565189542113879843219016388785533085940283555n,
  // Finite field 𝔽p over which we'll do calculations
  P: 2n ** 255n - 19n,
  // Subgroup order aka C
  n: 2n ** 252n + 27742317777372353535851937790883648493n,
  // Cofactor
  h: 8n,
  // Base point (x, y) aka generator point
  Gx: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  Gy: 46316835694926478169428394003475163141307993866256225615783033603165251855960n,
};

// Cleaner output this way.
export { CURVE };

type Hex = Uint8Array | string;
type PrivKey = Hex | bigint | number;
type PubKey = Hex | Point;
type SigType = Hex | Signature;
const B32 = 32;

// sqrt(-1) aka sqrt(a) aka 2^((p-1)/4)
const SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
const SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235n; // sqrt(ad - 1)
const INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578n; // 1 / sqrt(a-d)
const ONE_MINUS_D_SQ = 1159843021668779879193775521855586647937357759715417654439879720876111806838n; // 1-d^2
const D_MINUS_ONE_SQ = 40440834346308536858101042469323190826248399146238708352240133220865137265952n; // (d-1)^2

// Default Point works in default aka affine coordinates: (x, y)
// Extended Point works in extended coordinates: (x, y, z, t) ∋ (x=x/z, y=y/z, t=xy)
// https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Extended_coordinates
class ExtendedPoint {
  constructor(public x: bigint, public y: bigint, public z: bigint, public t: bigint) {}

  static BASE = new ExtendedPoint(CURVE.Gx, CURVE.Gy, 1n, mod(CURVE.Gx * CURVE.Gy));
  static ZERO = new ExtendedPoint(0n, 1n, 1n, 0n);
  static fromAffine(p: Point): ExtendedPoint {
    if (!(p instanceof Point)) {
      throw new TypeError('ExtendedPoint#fromAffine: expected Point');
    }
    if (p.equals(Point.ZERO)) return ExtendedPoint.ZERO;
    return new ExtendedPoint(p.x, p.y, 1n, mod(p.x * p.y));
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

  // Ristretto-related methods.

  // The hash-to-group operation applies Elligator twice and adds the results.
  // https://ristretto.group/formulas/elligator.html
  static fromRistrettoHash(hash: Uint8Array): ExtendedPoint {
    const r1 = bytes255ToNumberLE(hash.slice(0, B32));
    // const h = hash.slice(0, B32);
    const R1 = this.calcElligatorRistrettoMap(r1);
    const r2 = bytes255ToNumberLE(hash.slice(B32, B32 * 2));
    const R2 = this.calcElligatorRistrettoMap(r2);
    return R1.add(R2);
  }

  // Computes Elligator map for Ristretto
  // https://ristretto.group/formulas/elligator.html
  private static calcElligatorRistrettoMap(r0: bigint) {
    const { d } = CURVE;
    const r = mod(SQRT_M1 * r0 * r0); // 1
    const Ns = mod((r + 1n) * ONE_MINUS_D_SQ); // 2
    let c = -1n; // 3
    const D = mod((c - d * r) * mod(r + d)); // 4
    let { isValid: Ns_D_is_sq, value: s } = uvRatio(Ns, D); // 5
    let s_ = mod(s * r0); // 6
    if (!edIsNegative(s_)) s_ = mod(-s_);
    if (!Ns_D_is_sq) s = s_; // 7
    if (!Ns_D_is_sq) c = r; // 8
    const Nt = mod(c * (r - 1n) * D_MINUS_ONE_SQ - D); // 9
    const s2 = s * s;
    const W0 = mod((s + s) * D); // 10
    const W1 = mod(Nt * SQRT_AD_MINUS_ONE); // 11
    const W2 = mod(1n - s2); // 12
    const W3 = mod(1n + s2); // 13
    return new ExtendedPoint(mod(W0 * W3), mod(W2 * W1), mod(W1 * W3), mod(W0 * W2));
  }

  // Ristretto: Decoding to Extended Coordinates
  // https://ristretto.group/formulas/decoding.html
  static fromRistrettoBytes(bytes: Uint8Array): ExtendedPoint {
    const { a, d } = CURVE;
    const s = bytes255ToNumberLE(bytes);
    // 1. Check that s_bytes is the canonical encoding of a field element, or else abort.
    // 3. Check that s is non-negative, or else abort
    if (!equalBytes(numberToBytesPadded(s, B32), bytes) || edIsNegative(s)) {
      throw new Error('Cannot convert bytes to Ristretto Point');
    }
    const s2 = mod(s * s);
    const u1 = mod(1n + a * s2); // 4 (a is -1)
    const u2 = mod(1n - a * s2); // 5
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
    if (!isValid || edIsNegative(t) || y === 0n) {
      throw new Error('Cannot convert bytes to Ristretto Point');
    }
    return new ExtendedPoint(x, y, 1n, t);
  }

  // Ristretto: Encoding from Extended Coordinates
  // https://ristretto.group/formulas/encoding.html
  toRistrettoBytes(): Uint8Array {
    let { x, y, z, t } = this;
    const u1 = mod((z + y) * (z - y)); // 1
    const u2 = mod(x * y); // 2
    // Square root always exists
    const { value: invsqrt } = invertSqrt(mod(u1 * u2 ** 2n)); // 3
    const D1 = mod(invsqrt * u1); // 4
    const D2 = mod(invsqrt * u2); // 5
    const zInv = mod(D1 * D2 * t); // 6
    let D: bigint; // 7
    if (edIsNegative(t * zInv)) {
      [x, y] = [mod(y * SQRT_M1), mod(x * SQRT_M1)];
      D = mod(D1 * INVSQRT_A_MINUS_D);
    } else {
      D = D2; // 8
    }
    if (edIsNegative(x * zInv)) y = mod(-y); // 9
    let s = mod((z - y) * D); // 10 (check footer's note, no sqrt(-a))
    if (edIsNegative(s)) s = mod(-s);
    return numberToBytesPadded(s, B32); // 11
  }
  // Ristretto methods end.

  // Compare one point to another.
  equals(other: ExtendedPoint): boolean {
    const a = this;
    const b = other;
    const [T1, T2, Z1, Z2] = [a.t, b.t, a.z, b.z];
    return mod(T1 * Z2) === mod(T2 * Z1);
  }

  // Inverses point to one corresponding to (x, -y) in Affine coordinates.
  negate(): ExtendedPoint {
    return new ExtendedPoint(mod(-this.x), this.y, this.z, mod(-this.t));
  }

  // Fast algo for doubling Extended Point when curve's a=-1.
  // http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd
  // Cost: 3M + 4S + 1*a + 7add + 1*2.
  double(): ExtendedPoint {
    const X1 = this.x;
    const Y1 = this.y;
    const Z1 = this.z;
    const { a } = CURVE;
    const A = mod(X1 ** 2n);
    const B = mod(Y1 ** 2n);
    const C = mod(2n * Z1 ** 2n);
    const D = mod(a * A);
    const E = mod((X1 + Y1) ** 2n - A - B);
    const G = mod(D + B);
    const F = mod(G - C);
    const H = mod(D - B);
    const X3 = mod(E * F);
    const Y3 = mod(G * H);
    const T3 = mod(E * H);
    const Z3 = mod(F * G);
    return new ExtendedPoint(X3, Y3, Z3, T3);
  }

  // Fast algo for adding 2 Extended Points when curve's a=-1.
  // http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-4
  // Cost: 8M + 8add + 2*2.
  add(other: ExtendedPoint): ExtendedPoint {
    const X1 = this.x;
    const Y1 = this.y;
    const Z1 = this.z;
    const T1 = this.t;
    const X2 = other.x;
    const Y2 = other.y;
    const Z2 = other.z;
    const T2 = other.t;
    const A = mod((Y1 - X1) * (Y2 + X2));
    const B = mod((Y1 + X1) * (Y2 - X2));
    const F = mod(B - A);
    if (F === 0n) {
      // Same point.
      return this.double();
    }
    const C = mod(Z1 * 2n * T2);
    const D = mod(T1 * 2n * Z2);
    const E = mod(D + C);
    const G = mod(B + A);
    const H = mod(D - C);
    const X3 = mod(E * F);
    const Y3 = mod(G * H);
    const T3 = mod(E * H);
    const Z3 = mod(F * G);
    return new ExtendedPoint(X3, Y3, Z3, T3);
  }

  subtract(other: ExtendedPoint): ExtendedPoint {
    return this.add(other.negate());
  }

  // Non-constant-time multiplication. Uses double-and-add algorithm.
  // It's faster, but should only be used when you don't care about
  // an exposed private key e.g. sig verification.
  multiplyUnsafe(scalar: bigint): ExtendedPoint {
    if (!isValidScalar(scalar)) throw new TypeError('Point#multiply: expected number or bigint');
    let n = mod(BigInt(scalar), CURVE.n);
    if (n === 1n) return this;
    let p = ExtendedPoint.ZERO;
    let d: ExtendedPoint = this;
    while (n > 0n) {
      if (n & 1n) p = p.add(d);
      d = d.double();
      n >>= 1n;
    }
    return p;
  }

  private precomputeWindow(W: number): ExtendedPoint[] {
    const windows = 256 / W + 1;
    let points: ExtendedPoint[] = [];
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

  private wNAF(n: bigint, affinePoint?: Point): [ExtendedPoint, ExtendedPoint] {
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

    const windows = 256 / W + 1;
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
        n += 1n;
      }

      // Check if we're onto Zero point.
      // Add random point inside current window to f.
      if (wbits === 0) {
        f = f.add(window % 2 ? precomputes[offset].negate() : precomputes[offset]);
      } else {
        const cached = precomputes[offset + Math.abs(wbits) - 1];
        p = p.add(wbits < 0 ? cached.negate() : cached);
      }
    }
    return [p, f];
  }

  // Constant time multiplication.
  // Uses wNAF method. Windowed method may be 10% faster,
  // but takes 2x longer to generate and consumes 2x memory.
  multiply(scalar: number | bigint, affinePoint?: Point): ExtendedPoint {
    if (!isValidScalar(scalar)) throw new TypeError('Point#multiply: expected number or bigint');
    const n = mod(BigInt(scalar), CURVE.n);
    return ExtendedPoint.normalizeZ(this.wNAF(n, affinePoint))[0];
  }

  // Converts Extended point to default (x, y) coordinates.
  // Can accept precomputed Z^-1 - for example, from invertBatch.
  toAffine(invZ: bigint = invert(this.z)): Point {
    const x = mod(this.x * invZ);
    const y = mod(this.y * invZ);
    return new Point(x, y);
  }
}

// Stores precomputed values for points.
const pointPrecomputes = new WeakMap<Point, ExtendedPoint[]>();

// Default Point works in default aka affine coordinates: (x, y)
class Point {
  // Base point aka generator
  // public_key = Point.BASE * private_key
  static BASE: Point = new Point(CURVE.Gx, CURVE.Gy);
  // Identity point aka point at infinity
  // point = point + zero_point
  static ZERO: Point = new Point(0n, 1n);
  // We calculate precomputes for elliptic curve point multiplication
  // using windowed method. This specifies window size and
  // stores precomputed values. Usually only base point would be precomputed.
  _WINDOW_SIZE?: number;

  constructor(public x: bigint, public y: bigint) {}

  // "Private method", don't use it directly.
  _setWindowSize(windowSize: number) {
    this._WINDOW_SIZE = windowSize;
    pointPrecomputes.delete(this);
  }
  // Converts hash string or Uint8Array to Point.
  // Uses algo from RFC8032 5.1.3.
  static fromHex(hash: Hex) {
    const { d, P } = CURVE;
    const bytes = hash instanceof Uint8Array ? hash : hexToBytes(hash);
    if (bytes.length !== 32) throw new Error('Point.fromHex: expected 32 bytes');
    // 1.  First, interpret the string as an integer in little-endian
    // representation. Bit 255 of this number is the least significant
    // bit of the x-coordinate and denote this value x_0.  The
    // y-coordinate is recovered simply by clearing this bit.  If the
    // resulting value is >= p, decoding fails.
    const last = bytes[31];
    const normedLast = last & ~0x80;
    const isLastByteOdd = (last & 0x80) !== 0;
    const normed = Uint8Array.from(Array.from(bytes.slice(0, 31)).concat(normedLast));
    const y = bytesToNumberLE(normed);
    if (y >= P) {
      throw new Error('Point#fromHex expects hex <= Fp');
    }

    // 2.  To recover the x-coordinate, the curve equation implies
    // x^2 = (y^2 - 1) / (d y^2 + 1) (mod p).  The denominator is always
    // non-zero mod p.  Let u = y^2 - 1 and v = d y^2 + 1.
    const y2 = mod(y * y);
    const u = mod(y2 - 1n);
    const v = mod(d * y2 + 1n);
    let { isValid, value: x } = uvRatio(u, v);
    if (!isValid) throw new Error('Point.fromHex: invalid y coordinate');

    // 4.  Finally, use the x_0 bit to select the right square root.  If
    // x = 0, and x_0 = 1, decoding fails.  Otherwise, if x_0 != x mod
    // 2, set x <-- p - x.  Return the decoded point (x,y).
    const isXOdd = (x & 1n) === 1n;
    if (isLastByteOdd !== isXOdd) {
      x = mod(-x);
    }
    return new Point(x, y);
  }

  static async fromPrivateKey(privateKey: PrivKey) {
    const privBytes = await utils.sha512(normalizePrivateKey(privateKey));
    return Point.BASE.multiply(encodePrivate(privBytes));
  }

  /**
   * Converts point to compressed representation of its Y.
   * ECDSA uses `04${x}${y}` to represent long form and
   * `02${x}` / `03${x}` to represent short form,
   * where leading bit signifies positive or negative Y.
   * EDDSA (ed25519) uses short form.
   */
  toRawBytes(): Uint8Array {
    const hex = numberToHex(this.y);
    const u8 = new Uint8Array(B32);
    for (let i = hex.length - 2, j = 0; j < B32 && i >= 0; i -= 2, j++) {
      u8[j] = Number.parseInt(hex[i] + hex[i + 1], 16);
    }
    const mask = this.x & 1n ? 0x80 : 0;
    u8[B32 - 1] |= mask;
    return u8;
  }

  // Same as toRawBytes, but returns string.
  toHex(): string {
    return bytesToHex(this.toRawBytes());
  }

  // Converts to Montgomery; aka x coordinate of curve25519.
  // We don't have fromX25519, because we don't know sign!
  toX25519() {
    // curve25519 is birationally equivalent to ed25519
    // x, y: ed25519 coordinates
    // u, v: x25519 coordinates
    // u = (1 + y) / (1 - y)
    // See https://blog.filippo.io/using-ed25519-keys-for-encryption
    return mod((1n + this.y) * invert(1n - this.y));
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

  // Constant time multiplication.
  multiply(scalar: number | bigint): Point {
    return ExtendedPoint.fromAffine(this).multiply(scalar, this).toAffine();
  }
}

class Signature {
  constructor(public r: Point, public s: bigint) {}

  static fromHex(hex: Hex) {
    hex = ensureBytes(hex);
    const r = Point.fromHex(hex.slice(0, 32));
    const s = bytesToNumberLE(hex.slice(32));
    if (!isWithinCurveOrder(s)) throw new Error('Signature#fromHex expects s <= CURVE.n');
    return new Signature(r, s);
  }

  toRawBytes() {
    const numberBytes = hexToBytes(numberToHex(this.s)).reverse();
    const sBytes = new Uint8Array(B32);
    sBytes.set(numberBytes);
    const res = new Uint8Array(B32 * 2);
    res.set(this.r.toRawBytes());
    res.set(sBytes, 32);
    return res;
    // return concatTypedArrays(this.r.toRawBytes(), sBytes);
  }

  toHex() {
    return bytesToHex(this.toRawBytes());
  }
}

export { ExtendedPoint, Point, Signature, Signature as SignResult };

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
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
function bytesToHex(uint8a: Uint8Array): string {
  // pre-caching chars could speed this up 6x.
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += uint8a[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2) throw new Error('Expected valid hex');
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
  }
  return array;
}

function numberToHex(num: number | bigint): string {
  const hex = num.toString(16);
  return hex.length & 1 ? `0${hex}` : hex;
}

function numberToBytesPadded(num: bigint, length: number = B32) {
  const hex = numberToHex(num).padStart(length * 2, '0');
  return hexToBytes(hex).reverse();
}

// Little-endian check for first LE bit (last BE bit);
function edIsNegative(num: bigint) {
  return (mod(num) & 1n) === 1n;
}

function isValidScalar(num: number | bigint): boolean {
  if (typeof num === 'bigint' && num > 0n) return true;
  if (typeof num === 'number' && num > 0 && Number.isSafeInteger(num)) return true;
  return false;
}

// Little Endian
function bytesToNumberLE(uint8a: Uint8Array): bigint {
  let value = 0n;
  for (let i = 0; i < uint8a.length; i++) {
    value += BigInt(uint8a[i]) << (8n * BigInt(i));
  }
  return value;
}

function bytes255ToNumberLE(bytes: Uint8Array): bigint {
  return mod(bytesToNumberLE(bytes) & (2n ** 255n - 1n));
}
// -------------------------

function mod(a: bigint, b: bigint = CURVE.P) {
  const res = a % b;
  return res >= 0n ? res : b + res;
}

// Note: this egcd-based invert is faster than powMod-based one.
// Inverses number over modulo
function invert(number: bigint, modulo: bigint = CURVE.P): bigint {
  if (number === 0n || modulo <= 0n) {
    throw new Error('invert: expected positive integers');
  }
  // Eucledian GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
  let a = mod(number, modulo);
  let b = modulo;
  let [x, y, u, v] = [0n, 1n, 1n, 0n];
  while (a !== 0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    [b, a] = [a, r];
    [x, y] = [u, v];
    [u, v] = [m, n];
  }
  const gcd = b;
  if (gcd !== 1n) throw new Error('invert: does not exist');
  return mod(x, modulo);
}

function invertBatch(nums: bigint[], n: bigint = CURVE.P): bigint[] {
  const len = nums.length;
  const scratch = new Array(len);
  let acc = 1n;
  for (let i = 0; i < len; i++) {
    if (nums[i] === 0n) continue;
    scratch[i] = acc;
    acc = mod(acc * nums[i], n);
  }
  acc = invert(acc, n);
  for (let i = len - 1; i >= 0; i--) {
    if (nums[i] === 0n) continue;
    let tmp = mod(acc * nums[i], n);
    nums[i] = mod(acc * scratch[i], n);
    acc = tmp;
  }
  return nums;
}

// Does x ^ (2 ^ power) mod p. pow2(30, 4) == 30 ^ (2 ^ 4)
function pow2(x: bigint, power: bigint): bigint {
  const { P } = CURVE;
  let res = x;
  while (power-- > 0n) {
    res *= res;
    res %= P;
  }
  return res;
}

// Power to (p-5)/8 aka x^(2^252-3)
// Used to calculate y - the square root of y^2.
// Exponentiates it to very big number.
// We are unwrapping the loop because it's 2x faster.
// (2n**252n-3n).toString(2) would produce bits [250x 1, 0, 1]
// We are multiplying it bit-by-bit
function pow_2_252_3(x: bigint): bigint {
  const { P } = CURVE;
  const x2 = (x * x) % P;
  const b2 = (x2 * x) % P; // x^3, 11
  const b4 = (pow2(b2, 2n) * b2) % P; // x^15, 1111
  const b5 = (pow2(b4, 1n) * x) % P; // x^31
  const b10 = (pow2(b5, 5n) * b5) % P;
  const b20 = (pow2(b10, 10n) * b10) % P;
  const b40 = (pow2(b20, 20n) * b20) % P;
  const b80 = (pow2(b40, 40n) * b40) % P;
  const b160 = (pow2(b80, 80n) * b80) % P;
  const b240 = (pow2(b160, 80n) * b80) % P;
  const b250 = (pow2(b240, 10n) * b10) % P;
  const pow_p_5_8 = (pow2(b250, 2n) * x) % P;
  // ^ To pow to (p+3)/8, multiply it by x.
  return pow_p_5_8;
}

// Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
// prettier-ignore
function uvRatio(u: bigint, v: bigint): {isValid: boolean, value: bigint} {
  const v3 = mod(v * v * v);                  // v^3
  const v7 = mod(v3 * v3 * v);                // v^7
  let x = mod(u * v3 * pow_2_252_3(u * v7));  // (uv^3) * (uv^7)^(p-5)/8
  const vx2 = mod(v * x * x);                 // vx^2
  const root1 = x;                            // First root candidate
  const root2 = mod(x * SQRT_M1);             // Second root candidate
  const useRoot1 = vx2 === u;                 // If vx^2 = u (mod p), x is a square root
  const useRoot2 = vx2 === mod(-u);           // If vx^2 = -u, set x <-- x * 2^((p-1)/4)
  const noRoot = vx2 === mod(-u * SQRT_M1);   // There is no valid root, vx^2 = -u√(-1)
  if (useRoot1) x = root1;
  if (useRoot2 || noRoot) x = root2;          // We return root2 anyway, for const-time
  if (edIsNegative(x)) x = mod(-x);
  return { isValid: useRoot1 || useRoot2, value: x };
}

// Calculates 1/√(number)
function invertSqrt(number: bigint) {
  return uvRatio(1n, number);
}
// Math end

async function sha512ToNumberLE(...args: Uint8Array[]): Promise<bigint> {
  const messageArray = concatBytes(...args);
  const hash = await utils.sha512(messageArray);
  const value = bytesToNumberLE(hash);
  return mod(value, CURVE.n);
}

function keyPrefix(privateBytes: Uint8Array) {
  return privateBytes.slice(B32);
}

function encodePrivate(privateBytes: Uint8Array): bigint {
  const last = B32 - 1;
  const head = privateBytes.slice(0, B32);
  head[0] &= 248;
  head[last] &= 127;
  head[last] |= 64;
  return mod(bytesToNumberLE(head), CURVE.n);
}

function equalBytes(b1: Uint8Array, b2: Uint8Array) {
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

function ensureBytes(hash: Hex): Uint8Array {
  return hash instanceof Uint8Array ? hash : hexToBytes(hash);
}

function isWithinCurveOrder(num: bigint): boolean {
  return 0 < num && num < CURVE.n;
}

function normalizePrivateKey(key: PrivKey): Uint8Array {
  let num: bigint;
  if (typeof key === 'bigint' || (Number.isSafeInteger(key) && key > 0)) {
    num = BigInt(key);
    return hexToBytes(num.toString(16).padStart(B32 * 2, '0'));
  } else if (typeof key === 'string') {
    if (key.length !== 64) throw new Error('Expected 32 bytes of private key');
    return hexToBytes(key);
  } else if (key instanceof Uint8Array) {
    if (key.length !== 32) throw new Error('Expected 32 bytes of private key');
    return key;
  } else {
    throw new TypeError('Expected valid private key');
  }
}

export function getPublicKey(privateKey: Uint8Array | bigint | number): Promise<Uint8Array>;
export function getPublicKey(privateKey: string): Promise<string>;
export async function getPublicKey(privateKey: PrivKey) {
  const key = await Point.fromPrivateKey(privateKey);
  return typeof privateKey === 'string' ? key.toHex() : key.toRawBytes();
}

export function sign(hash: Uint8Array, privateKey: Hex): Promise<Uint8Array>;
export function sign(hash: string, privateKey: Hex): Promise<string>;
export async function sign(hash: Hex, privateKey: Hex) {
  const privBytes = await utils.sha512(normalizePrivateKey(privateKey));
  const p = encodePrivate(privBytes);
  const P = Point.BASE.multiply(p);
  const msg = ensureBytes(hash);
  const r = await sha512ToNumberLE(keyPrefix(privBytes), msg);
  const R = Point.BASE.multiply(r);
  const h = await sha512ToNumberLE(R.toRawBytes(), P.toRawBytes(), msg);
  const S = mod(r + h * p, CURVE.n);
  const sig = new Signature(R, S);
  return typeof hash === 'string' ? sig.toHex() : sig.toRawBytes();
}

export async function verify(signature: SigType, hash: Hex, publicKey: PubKey): Promise<boolean> {
  hash = ensureBytes(hash);
  if (!(publicKey instanceof Point)) publicKey = Point.fromHex(publicKey);
  if (!(signature instanceof Signature)) signature = Signature.fromHex(signature);
  const hs = await sha512ToNumberLE(signature.r.toRawBytes(), publicKey.toRawBytes(), hash);
  const Ph = ExtendedPoint.fromAffine(publicKey).multiplyUnsafe(hs);
  const Gs = ExtendedPoint.BASE.multiply(signature.s);
  const RPh = ExtendedPoint.fromAffine(signature.r).add(Ph);
  return RPh.subtract(Gs).multiplyUnsafe(8n).equals(ExtendedPoint.ZERO);
}

// Enable precomputes. Slows down first publicKey computation by 20ms.
Point.BASE._setWindowSize(8);

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
  randomPrivateKey: (bytesLength: number = 32): Uint8Array => {
    // @ts-ignore
    if (typeof window == 'object' && 'crypto' in window) {
      // @ts-ignore
      return window.crypto.getRandomValues(new Uint8Array(bytesLength));
      // @ts-ignore
    } else if (typeof process === 'object' && 'node' in process.versions) {
      // @ts-ignore
      const { randomBytes } = require('crypto');
      return new Uint8Array(randomBytes(bytesLength).buffer);
    } else {
      throw new Error("The environment doesn't have randomBytes function");
    }
  },
  sha512: async (message: Uint8Array): Promise<Uint8Array> => {
    // @ts-ignore
    if (typeof window == 'object' && 'crypto' in window) {
      // @ts-ignore
      const buffer = await window.crypto.subtle.digest('SHA-512', message.buffer);
      // @ts-ignore
      return new Uint8Array(buffer);
      // @ts-ignore
    } else if (typeof process === 'object' && 'node' in process.versions) {
      // @ts-ignore
      const { createHash } = require('crypto');
      const hash = createHash('sha512');
      hash.update(message);
      return Uint8Array.from(hash.digest());
    } else {
      throw new Error("The environment doesn't have sha512 function");
    }
  },
  precompute(windowSize = 8, point = Point.BASE): Point {
    const cached = point.equals(Point.BASE) ? point : new Point(point.x, point.y);
    cached._setWindowSize(windowSize);
    cached.multiply(1n);
    return cached;
  },
};

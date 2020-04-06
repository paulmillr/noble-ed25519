/*! noble-ed25519 - MIT License (c) Paul Miller (paulmillr.com) */

// https://ed25519.cr.yp.to
// https://tools.ietf.org/html/rfc8032
// https://en.wikipedia.org/wiki/EdDSA
// Thanks DJB!

const CURVE = {
  // Params: a, b
  a: -1n,
  // Equal to -121665/121666 over finite field.
  // Negative number is P - number, and division is modInverse(number, P)
  d: 37095705934669439343138083508754565189542113879843219016388785533085940283555n,
  // Finite field 𝔽p over which we'll do calculations
  P: 2n ** 255n - 19n,
  // Subgroup order aka prime_order
  n: 2n ** 252n + 27742317777372353535851937790883648493n,
  // Cofactor
  h: 8n,
  // Base point (x, y) aka generator point
  Gx: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  Gy: 46316835694926478169428394003475163141307993866256225615783033603165251855960n
};

// Cleaner output this way.
export {CURVE};

// The 8-torsion subgroup ℰ8.
// Those are "buggy" points, if you multiply them by 8, you'll receive Point.ZERO.
// Ported from curve25519-dalek.
const TORSION_SUBGROUP = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  '0000000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa'
];

type PrivKey = Uint8Array | string | bigint | number;
type PubKey = Uint8Array | string | Point;
type Hex = Uint8Array | string;
type Signature = Uint8Array | string | SignResult;

const ENCODING_LENGTH = 32;
const P = CURVE.P;
const PRIME_ORDER = CURVE.n;
const I = powMod(2n, (P - 1n) / 4n, P);

// Default Point works in default aka affine coordinates: (x, y)
// Extended Point works in extended coordinates: (x, y, z, t) ∋ (x=x/z, y=y/z, t=xy)
// https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Extended_coordinates
class ExtendedPoint {
  static BASE = new ExtendedPoint(CURVE.Gx, CURVE.Gy, 1n, mod(CURVE.Gx * CURVE.Gy));
  static ZERO = new ExtendedPoint(0n, 1n, 1n, 0n);
  static fromAffine(p: Point): ExtendedPoint {
    if (p.equals(Point.ZERO)) return ExtendedPoint.ZERO;
    return new ExtendedPoint(p.x, p.y, 1n, mod(p.x * p.y));
  }

  constructor(public x: bigint, public y: bigint, public z: bigint, public t: bigint) {}

  // Takes a bunch of Jacobian Points but executes only one
  // modInverse on all of them. modInverse is very slow operation,
  // so this improves performance massively.
  static batchAffine(points: ExtendedPoint[]): Point[] {
    const toInv = batchInverse(points.map(p => p.z));
    return points.map((p, i) => p.toAffine(toInv[i]));
  }

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
    const _a = this;
    const X1 = _a.x,
      Y1 = _a.y,
      Z1 = _a.z;
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

  // Non-constant-time multiplication. Uses double-and-add algorithm.
  // It's faster, but should only be used when you don't care about
  // an exposed private key e.g. sig verification.
  multiplyUnsafe(scalar: bigint): ExtendedPoint {
    if (typeof scalar !== 'number' && typeof scalar !== 'bigint') {
      throw new TypeError('Point#multiply: expected number or bigint');
    }
    let n = mod(BigInt(scalar), PRIME_ORDER);
    if (n <= 0) {
      throw new Error('Point#multiply: invalid scalar, expected positive integer');
    }
    let p = ExtendedPoint.ZERO;
    let d: ExtendedPoint = this;
    while (n > 0n) {
      if (n & 1n) p = p.add(d);
      d = d.double();
      n >>= 1n;
    }
    return p;
  }

  // Converts Extended point to default (x, y) coordinates.
  // Can accept precomputed Z^-1 - for example, from batchInverse.
  toAffine(invZ: bigint = modInverse(this.z)): Point {
    const x = mod(this.x * invZ);
    const y = mod(this.y * invZ);
    return new Point(x, y);
  }
}

// Stores precomputed values for points.
const pointPrecomputes = new WeakMap();

// Default Point works in default aka affine coordinates: (x, y)
export class Point {
  // Base point aka generator
  // public_key = Point.BASE * private_key
  static BASE: Point = new Point(CURVE.Gx, CURVE.Gy);
  // Identity point aka point at infinity
  // point = point + zero_point
  static ZERO: Point = new Point(0n, 1n);
  // We calculate precomputes for elliptic curve point multiplication
  // using windowed method. This specifies window size and
  // stores precomputed values. Usually only base point would be precomputed.
  private WINDOW_SIZE?: number;

  constructor(public x: bigint, public y: bigint) {}

  // "Private method", don't use it directly.
  _setWindowSize(windowSize: number) {
    this.WINDOW_SIZE = windowSize;
    pointPrecomputes.delete(this);
  }
  // Converts hash string or Uint8Array to Point.
  // Uses algo from RFC8032 5.1.3.
  static fromHex(hash: Hex) {
    const { d } = CURVE;
    const bytes = hash instanceof Uint8Array ? hash : hexToArray(hash);
    const len = bytes.length - 1;
    const normedLast = bytes[len] & ~0x80;
    const isLastByteOdd = (bytes[len] & 0x80) !== 0;
    const normed = Uint8Array.from(Array.from(bytes.slice(0, len)).concat(normedLast));
    const y = arrayToNumberLE(normed);
    if (y >= P) {
      throw new Error('Point#fromHex expects hex <= Fp');
    }
    const sqrY = y * y;
    const sqrX = mod((sqrY - 1n) * modInverse(d * sqrY + 1n), P);
    let x = powMod(sqrX, (P + 3n) / 8n, P);
    if (mod(x * x - sqrX) !== 0n) {
      x = mod(x * I);
    }
    const isXOdd = (x & 1n) === 1n;
    if (isLastByteOdd !== isXOdd) {
      x = mod(-x);
    }
    return new Point(x, y);
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
    const u8 = new Uint8Array(ENCODING_LENGTH);
    for (let i = hex.length - 2, j = 0; j < ENCODING_LENGTH && i >= 0; i -= 2, j++) {
      u8[j] = parseInt(hex[i] + hex[i + 1], 16);
    }
    const mask = this.x & 1n ? 0x80 : 0;
    u8[ENCODING_LENGTH - 1] |= mask;
    return u8;
  }

  // Same as toRawBytes, but returns string.
  toHex(): string {
    return arrayToHex(this.toRawBytes());
  }

  // Converts to Montgomery; aka x coordinate of curve25519.
  // We don't have fromX25519, because we don't know sign!
  toX25519() {
    // curve25519 is birationally equivalent to ed25519
    // x, y: ed25519 coordinates
    // u, v: x25519 coordinates
    // u = (1 + y) / (1 - y)
    // See https://blog.filippo.io/using-ed25519-keys-for-encryption
    return mod((1n + this.y) * modInverse(1n - this.y));
  }

  equals(other: Point): boolean {
    return this.x === other.x && this.y === other.y;
  }

  negate(): Point {
    return new Point(this.x, mod(-this.y));
  }

  // Adds point to itself. http://hyperelliptic.org/EFD/g1p/auto-twisted.html
  add(other: Point): Point {
    if (!(other instanceof Point)) {
      throw new TypeError('Point#add: expected Point');
    }
    const { d } = CURVE;
    const X1 = this.x;
    const Y1 = this.y;
    const X2 = other.x;
    const Y2 = other.y;
    const X3 = (X1 * Y2 + Y1 * X2) * modInverse(1n + d * X1 * X2 * Y1 * Y2);
    const Y3 = (Y1 * Y2 + X1 * X2) * modInverse(1n - d * X1 * X2 * Y1 * Y2);
    return new Point(mod(X3), mod(Y3));
  }

  subtract(other: Point) {
    return this.add(other.negate());
  }

  private precomputeWindow(W: number): ExtendedPoint[] {
    const cached = pointPrecomputes.get(this);
    if (cached) return cached;
    const windows = 256 / W + 1;
    let points: ExtendedPoint[] = [];
    let p = ExtendedPoint.fromAffine(this);
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
    if (W !== 1) {
      points = ExtendedPoint.batchAffine(points).map(ExtendedPoint.fromAffine);
      pointPrecomputes.set(this, points);
    }
    return points;
  }

  private wNAF(n: bigint) {
    const W = this.WINDOW_SIZE || 1;
    if (256 % W) {
      throw new Error('Point#multiply: Invalid precomputation window, must be power of 2');
    }
    const precomputes = this.precomputeWindow(W);
    let p = ExtendedPoint.ZERO;
    let f = ExtendedPoint.ZERO

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
        f = f.add(precomputes[offset]);
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
  multiply(scalar: bigint, isAffine: false): ExtendedPoint;
  multiply(scalar: bigint, isAffine?: true): Point;
  multiply(scalar: bigint, isAffine = true): Point | ExtendedPoint {
    if (typeof scalar !== 'number' && typeof scalar !== 'bigint') {
      throw new TypeError('Point#multiply: expected number or bigint');
    }
    const n = mod(BigInt(scalar), PRIME_ORDER);
    if (n <= 0) {
      throw new Error('Point#multiply: invalid scalar, expected positive integer');
    }
    const [point, fake] = this.wNAF(n);
    return isAffine ? ExtendedPoint.batchAffine([point, fake])[0] : point;
  }
}

export class SignResult {
  constructor(public r: Point, public s: bigint) {}

  static fromHex(hex: Hex) {
    hex = ensureArray(hex);
    const r = Point.fromHex(hex.slice(0, 32));
    const s = arrayToNumberLE(hex.slice(32));
    return new SignResult(r, s);
  }

  toRawBytes() {
    const numberBytes = hexToArray(numberToHex(this.s)).reverse();
    const sBytes = new Uint8Array(ENCODING_LENGTH);
    sBytes.set(numberBytes);
    const res = new Uint8Array(64);
    res.set(this.r.toRawBytes());
    res.set(sBytes, 32);
    return res;
    // return concatTypedArrays(this.r.toRawBytes(), sBytes);
  }

  toHex() {
    return arrayToHex(this.toRawBytes());
  }
}

// SHA512 implementation.
let sha512: (message: Uint8Array) => Promise<Uint8Array>;
let generateRandomPrivateKey = (bytesLength: number = 32) => new Uint8Array(bytesLength);

if (typeof window == 'object' && 'crypto' in window) {
  sha512 = async (message: Uint8Array) => {
    const buffer = await window.crypto.subtle.digest('SHA-512', message.buffer);
    return new Uint8Array(buffer);
  };
  generateRandomPrivateKey = (bytesLength: number = 32): Uint8Array => {
    return window.crypto.getRandomValues(new Uint8Array(bytesLength));
  };
} else if (typeof process === 'object' && 'node' in process.versions) {
  const req = require;
  const { createHash, randomBytes } = req('crypto');
  sha512 = async (message: Uint8Array) => {
    const hash = createHash('sha512');
    hash.update(message);
    return Uint8Array.from(hash.digest());
  };
  generateRandomPrivateKey = (bytesLength: number = 32): Uint8Array => {
    return new Uint8Array(randomBytes(bytesLength).buffer);
  };
} else {
  throw new Error("The environment doesn't have sha512 function");
}

function concatTypedArrays(...arrays: Uint8Array[]): Uint8Array {
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
function arrayToHex(uint8a: Uint8Array): string {
  // pre-caching chars could speed this up 6x.
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += uint8a[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function pad64(num: number | bigint): string {
  return num.toString(16).padStart(64, '0');
}

function numberToHex(num: number | bigint): string {
  const hex = num.toString(16);
  return hex.length & 1 ? `0${hex}` : hex;
}

function hexToArray(hex: string): Uint8Array {
  hex = hex.length & 1 ? `0${hex}` : hex;
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    let j = i * 2;
    array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
  }
  return array;
}

// Little Endian
function arrayToNumberLE(uint8a: Uint8Array): bigint {
  let value = 0n;
  for (let i = 0; i < uint8a.length; i++) {
    value += BigInt(uint8a[i]) << (8n * BigInt(i));
  }
  return value;
}
// -------------------------

function mod(a: bigint, b: bigint = P) {
  const res = a % b;
  return res >= 0n ? res : b + res;
}

function powMod(x: bigint, power: bigint, order: bigint) {
  let res = 1n;
  while (power > 0) {
    if (power & 1n) {
      res = mod(res * x, order);
    }
    power >>= 1n;
    x = mod(x * x, order);
  }
  return res;
}

// Eucledian GCD
// https://brilliant.org/wiki/extended-euclidean-algorithm/
function egcd(a: bigint, b: bigint) {
  let [x, y, u, v] = [0n, 1n, 1n, 0n];
  while (a !== 0n) {
    let q = b / a;
    let r = b % a;
    let m = x - u * q;
    let n = y - v * q;
    [b, a] = [a, r];
    [x, y] = [u, v];
    [u, v] = [m, n];
  }
  let gcd = b;
  return [gcd, x, y];
}

function modInverse(number: bigint, modulo: bigint = P) {
  if (number === 0n || modulo <= 0n) {
    console.log(number);
    throw new Error('modInverse: expected positive integers');
  }
  let [gcd, x] = egcd(mod(number, modulo), modulo);
  if (gcd !== 1n) {
    throw new Error('modInverse: does not exist');
  }
  return mod(x, modulo);
}

function batchInverse(nums: bigint[], n: bigint = P): bigint[] {
  const len = nums.length;
  const scratch = new Array(len);
  let acc = 1n;
  for (let i = 0; i < len; i++) {
    if (nums[i] === 0n) continue;
    scratch[i] = acc;
    acc = mod(acc * nums[i], n);
  }
  acc = modInverse(acc, n);
  for (let i = len - 1; i >= 0; i--) {
    if (nums[i] === 0n) continue;
    let tmp = mod(acc * nums[i], n);
    nums[i] = mod(acc * scratch[i], n);
    acc = tmp;
  }
  return nums;
}

async function sha512ToNumberLE(...args: Uint8Array[]): Promise<bigint> {
  const messageArray = concatTypedArrays(...args);
  const hash = await sha512(messageArray);
  const value = arrayToNumberLE(hash);
  return mod(value, PRIME_ORDER);
}

function keyPrefix(privateBytes: Uint8Array) {
  return privateBytes.slice(ENCODING_LENGTH);
}

function encodePrivate(privateBytes: Uint8Array): bigint {
  const last = ENCODING_LENGTH - 1;
  const head = privateBytes.slice(0, ENCODING_LENGTH);
  head[0] &= 248;
  head[last] &= 127;
  head[last] |= 64;

  return arrayToNumberLE(head);
}

function ensureArray(hash: Hex): Uint8Array {
  return hash instanceof Uint8Array ? hash : hexToArray(hash);
}

function ensurePrivInputArray(privateKey: PrivKey): Uint8Array {
  if (privateKey instanceof Uint8Array) return privateKey;
  if (typeof privateKey === 'string') return hexToArray(privateKey.padStart(64, '0'));
  return hexToArray(pad64(BigInt(privateKey)));
}

export function getPublicKey(privateKey: Uint8Array): Promise<Uint8Array>;
export function getPublicKey(privateKey: string): Promise<string>;
export function getPublicKey(privateKey: bigint | number): Promise<Uint8Array>;
export async function getPublicKey(privateKey: PrivKey) {
  const privBytes = await sha512(ensurePrivInputArray(privateKey));
  const publicKey = Point.BASE.multiply(encodePrivate(privBytes));
  return typeof privateKey === 'string' ? publicKey.toHex() : publicKey.toRawBytes();
}

export function sign(hash: Uint8Array, privateKey: Hex): Promise<Uint8Array>;
export function sign(hash: string, privateKey: Hex): Promise<string>;
export async function sign(hash: Hex, privateKey: Hex) {
  const privBytes = await sha512(ensurePrivInputArray(privateKey));
  const p = encodePrivate(privBytes);
  const P = Point.BASE.multiply(p);
  const msg = ensureArray(hash);
  const r = await sha512ToNumberLE(keyPrefix(privBytes), msg);
  const R = Point.BASE.multiply(r);
  const h = await sha512ToNumberLE(R.toRawBytes(), P.toRawBytes(), msg);
  const S = mod(r + h * p, PRIME_ORDER);
  const sig = new SignResult(R, S);
  return typeof hash === 'string' ? sig.toHex() : sig.toRawBytes();
}

export async function verify(signature: Signature, hash: Hex, publicKey: PubKey) {
  hash = ensureArray(hash);
  if (!(publicKey instanceof Point)) publicKey = Point.fromHex(publicKey);
  if (!(signature instanceof SignResult)) signature = SignResult.fromHex(signature);
  const h = await sha512ToNumberLE(signature.r.toRawBytes(), publicKey.toRawBytes(), hash);
  const Ph = ExtendedPoint.fromAffine(publicKey).multiplyUnsafe(h);
  const Gs = Point.BASE.multiply(signature.s, false);
  const RPh = ExtendedPoint.fromAffine(signature.r).add(Ph);
  return Gs.equals(RPh);
}

// Enable precomputes. Slows down first publicKey computation by 20ms.
Point.BASE._setWindowSize(8);

export const utils = {
  generateRandomPrivateKey,

  precompute(windowSize = 8, point = Point.BASE): Point {
    const cached = point.equals(Point.BASE) ? point : new Point(point.x, point.y);
    cached._setWindowSize(windowSize);
    cached.multiply(1n);
    return cached;
  }
};

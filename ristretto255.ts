/*! noble-ristretto255 - MIT License (c) Paul Miller (paulmillr.com) */
/* Optional file — it's unnecessary for ed25519 itself */

// Ristretto is a technique for constructing prime order elliptic curve
// groups with non-malleable encodings. It extends Mike Hamburg's Decaf
// approach to cofactor elimination to support cofactor-8 curves such as Curve25519.

// In particular, this allows an existing Curve25519 library to implement
// a prime-order group with only a thin abstraction layer, and makes it
// possible for systems using Ed25519 signatures to be safely extended
// with zero-knowledge protocols, with no additional cryptographic assumptions
// and minimal code changes.
// https://ristretto.group

import { ExtendedPoint } from '.';

const mask64Bits = (1n << 64n) - 1n;
const low51bitMask = (1n << 51n) - 1n;

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
  Gy: 46316835694926478169428394003475163141307993866256225615783033603165251855960n,
};

// Edwards `2*d` value, equal to `2*(-121665/121666) mod p`.
const D2 = 16295367250680780974490674513165176452449235426866156013048779062215315747161n;

// sqrt(-1 % P)
const SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;

// `= 1/sqrt(a-d)`, where `a = -1 (mod p)`, `d` are the Edwards curve parameters.
const INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578n;

// `= sqrt(a*d - 1)`, where `a = -1 (mod p)`, `d` are the Edwards curve parameters.
const SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235n;

function isNegative(t: bigint) {
  const bytes = toBytesLE(mod(t));
  return Boolean(bytes[0] & 1);
}

function mod(a: bigint, b: bigint = CURVE.P) {
  const res = a % b;
  return res >= 0 ? res : b + res;
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

export function modInverse(number: bigint, modulo: bigint = P) {
  if (number === 0n || modulo <= 0n) {
    throw new Error('modInverse: expected positive integers');
  }
  let [gcd, x] = egcd(mod(number, modulo), modulo);
  if (gcd !== 1n) {
    throw new Error('modInverse: does not exist');
  }
  return mod(x, modulo);
}

// Select sets v to a if cond == 1, and to b if cond == 0.
function select(t: bigint, other: bigint, choice: 0n | 1n | 0 | 1 | boolean) {
  return choice ? mod(t) : mod(other);
}

function condNegative(t: bigint, choice: 0n | 1n | 0 | 1 | boolean) {
  return select(mod(-t), t, choice);
}

// Attempt to compute `sqrt(1/self)` in constant time.
function invertSqrt(t: bigint) {
  return sqrtRatio(1n, t);
}

function pow2k(t: bigint, power: bigint) {
  let res = t;
  while (power-- > 0) {
    res = res * res;
  }
  return res;
}

function pow22501(t: bigint) {
  const t0 = mod(t * t);
  const t1 = mod(t0 ** 4n);
  const t2 = mod(t * t1);
  const t3 = mod(t0 * t2);
  const t5 = mod(t2 * t3 * t3);
  let t7 = t5;
  for (let i = 0; i < 5; i++) {
    t7 *= t7;
    t7 %= P;
  }
  t7 *= t5;
  t7 %= P;
  let t9 = t7;
  for (let i = 0; i < 10; i++) {
    t9 *= t9;
    t9 %= P;
  }
  t9 *= t7;
  t9 %= P;
  let t13 = t9;
  for (let i = 0; i < 20; i++) {
    t13 *= t13;
    t13 %= P;
  }
  t13 *= t9;
  t13 %= P;
  for (let i = 0; i < 10; i++) {
    t13 *= t13;
    t13 %= P;
  }
  t13 *= t7;
  t13 %= P;
  let t15 = t13;
  for (let i = 0; i < 50; i++) {
    t15 *= t15;
    t15 %= P;
  }
  t15 *= t13;
  t15 %= P;
  let t19 = t15;
  for (let i = 0; i < 100; i++) {
    t19 *= t19;
    t19 %= P;
  }
  t19 *= t15;
  t19 %= P;
  for (let i = 0; i < 50; i++) {
    t19 *= t19;
    t19 %= P;
  }
  t19 *= t13;
  t19 %= P;
  return [t19, t3];
}

function powP58(t: bigint) {
  const [t19] = pow22501(t);
  return pow2k(t19, 2n) * t;
}

export function sqrtRatio(t: bigint, v: bigint) {
  // Using the same trick as in ed25519 decoding, we merge the
  // inversion, the square root, and the square test as follows.
  //
  // To compute sqrt(α), we can compute β = α^((p+3)/8).
  // Then β^2 = ±α, so multiplying β by sqrt(-1) if necessary
  // gives sqrt(α).
  //
  // To compute 1/sqrt(α), we observe that
  //    1/β = α^(p-1 - (p+3)/8) = α^((7p-11)/8)
  //                            = α^3 * (α^7)^((p-5)/8).
  //
  // We can therefore compute sqrt(u/v) = sqrt(u)/sqrt(v)
  // by first computing
  //    r = u^((p+3)/8) v^(p-1-(p+3)/8)
  //      = u u^((p-5)/8) v^3 (v^7)^((p-5)/8)
  //      = (uv^3) (uv^7)^((p-5)/8).
  //
  // If v is nonzero and u/v is square, then r^2 = ±u/v,
  //                                     so vr^2 = ±u.
  // If vr^2 =  u, then sqrt(u/v) = r.
  // If vr^2 = -u, then sqrt(u/v) = r*sqrt(-1).
  //
  // If v is zero, r is also zero.
  const v3 = mod(v * v * v);
  const v7 = mod(v3 * v3 * v);
  let r = mod(powP58(t * v7) * t * v3);
  const check = mod(r * r * v);
  const i = SQRT_M1;
  const correctSignSqrt = check === t;
  const flippedSignSqrt = check === mod(-t);
  const flippedSignSqrtI = check === mod(mod(-t) * i);
  const rPrime = mod(SQRT_M1 * r);
  r = select(rPrime, r, flippedSignSqrt || flippedSignSqrtI);
  r = condNegative(r, isNegative(r));
  const isNotZeroSquare = correctSignSqrt || flippedSignSqrt;
  return { isNotZeroSquare, value: mod(r) };
}

function toBytesBE(t: bigint, length: number = 0) {
  let hex = t.toString(16);
  hex = hex.length & 1 ? `0${hex}` : hex;
  hex = hex.padStart(length * 2, '0');
  const len = hex.length / 2;
  const u8 = new Uint8Array(len);
  for (let j = 0, i = 0; i < hex.length; i += 2, j++) {
    u8[j] = parseInt(hex[i] + hex[i + 1], 16);
  }
  return u8;
}

function toBytesLE(t: bigint, length = 0) {
  return toBytesBE(t, length).reverse();
}

// CondSwap swaps a and b if cond == 1 or leaves them unchanged if cond == 0.
function condSwap(t: bigint, other: bigint, choice: 0n | 1n | 0 | 1 | boolean) {
  choice = BigInt(choice) as 0n | 1n;
  const mask = choice !== 0n ? mask64Bits : choice;
  const tmp = mask & (t ^ other);
  return [mod(t ^ tmp), mod(other ^ tmp)];
}

function load8(input: Uint8Array, padding = 0) {
  return (
    BigInt(input[0 + padding]) |
    (BigInt(input[1 + padding]) << 8n) |
    (BigInt(input[2 + padding]) << 16n) |
    (BigInt(input[3 + padding]) << 24n) |
    (BigInt(input[4 + padding]) << 32n) |
    (BigInt(input[5 + padding]) << 40n) |
    (BigInt(input[6 + padding]) << 48n) |
    (BigInt(input[7 + padding]) << 56n)
  );
}

function BigInt_fromBytes(bytes: Uint8Array) {
  const octet1 = load8(bytes, 0) & low51bitMask;
  const octet2 = (load8(bytes, 6) >> 3n) & low51bitMask;
  const octet3 = (load8(bytes, 12) >> 6n) & low51bitMask;
  const octet4 = (load8(bytes, 19) >> 1n) & low51bitMask;
  const octet5 = (load8(bytes, 24) >> 12n) & low51bitMask;
  return mod(octet1 + (octet2 << 51n) + (octet3 << 102n) + (octet4 << 153n) + (octet5 << 204n));
}

export const P = CURVE.P;
export const PRIME_ORDER = CURVE.n;

export class ProjectiveP1xP1 {
  static ZERO = new ProjectiveP1xP1(0n, 1n, 1n, 1n);

  constructor(public x: bigint, public y: bigint, public z: bigint, public T: bigint) {
    this.x = mod(this.x);
    this.y = mod(this.y);
    this.z = mod(this.z);
    this.T = mod(this.T);
  }
}

export class ProjectiveP2 {
  static fromP1xP1(point: ProjectiveP1xP1) {
    return new ProjectiveP2(mod(point.x * point.T), mod(point.y * point.T), mod(point.z * point.T));
  }

  static fromP3(point: ProjectiveP3) {
    return new ProjectiveP2(point.x, point.y, point.z);
  }

  static ZERO = new ProjectiveP2(0n, 1n, 1n);

  constructor(public x: bigint, public y: bigint, public z: bigint) {
    this.x = mod(this.x);
    this.y = mod(this.y);
    this.z = mod(this.z);
  }

  double() {
    const squaredX = this.x ** 2n;
    const squaredY = this.y ** 2n;
    const squaredZ = this.z ** 2n;
    const squaredZ2 = mod(squaredZ + squaredZ);
    const xPlusYSquared = mod(this.x + this.y) ** 2n;
    const y = mod(squaredY + squaredX);
    const z = mod(squaredY - squaredX);
    const x = mod(xPlusYSquared - y);
    const T = mod(squaredZ2 - this.z);
    return new ProjectiveP1xP1(x, y, z, T);
  }
}

export class ProjectiveP3 {
  static ZERO = new ProjectiveP3(0n, 1n, 1n, 0n);
  static fromP1xP1(point: ProjectiveP1xP1) {
    return new ProjectiveP3(
      mod(point.x * point.T),
      mod(point.y * point.z),
      mod(point.z * point.T),
      mod(point.x * point.y)
    );
  }

  static fromP2(point: ProjectiveP2) {
    return new ProjectiveP3(
      mod(point.x * point.z),
      mod(point.y * point.z),
      mod(point.z ** 2n),
      mod(point.x * point.y)
    );
  }


  constructor(public x: bigint, public y: bigint, public z: bigint, public T: bigint) {
    this.x = mod(this.x);
    this.y = mod(this.y);
    this.z = mod(this.z);
    this.T = mod(this.T);
  }

  toProjectiveNielsPoint() {
    return new ProjectiveP3(mod(this.y + this.x), mod(this.y - this.x), this.z, mod(this.T * D2));
  }

  toExtendedProjective() {
    return new ProjectiveP3(
      mod(this.x * this.z),
      mod(this.y * this.z),
      mod(this.z * this.z),
      mod(this.x * this.y)
    );
  }

  toExtendedCompleted() {
    return new ProjectiveP3(
      mod(this.x * this.T),
      mod(this.y * this.z),
      mod(this.z * this.T),
      mod(this.x * this.y)
    );
  }

  addCached(other: ProjectiveCached) {
    const yPlusX = this.y + this.x;
    const yMinusX = this.y - this.x;
    const PP = yPlusX * other.yPlusX;
    const MM = yMinusX * other.yMinusX;
    const TT2 = this.T * other.T2d;
    const ZZ = this.z * other.z;
    const ZZ2 = ZZ + ZZ;
    return new ProjectiveP1xP1(mod(PP - MM), mod(PP + MM), mod(ZZ2 + TT2), mod(ZZ2 - TT2));
  }

  subtractCached(other: ProjectiveCached) {
    const yPlusX = this.y + this.x;
    const yMinusX = this.y - this.x;
    const PP = yPlusX * other.yMinusX;
    const MM = yMinusX * other.yPlusX;
    const TT2 = this.T * other.T2d;
    const ZZ = this.z * other.z;
    const ZZ2 = ZZ + ZZ;
    return new ProjectiveP1xP1(mod(PP - MM), mod(PP + MM), mod(ZZ2 - TT2), mod(ZZ2 + TT2));
  }

  addAffine(other: AffineCached) {
    const yPlusX = this.y + this.x;
    const yMinusX = this.y - this.x;
    const PP = yPlusX * other.yPlusX;
    const MM = yMinusX * other.yMinusX;
    const TT2 = this.T * other.T2d;
    const ZZ = this.z * this.z;
    const ZZ2 = ZZ + ZZ;
    return new ProjectiveP1xP1(mod(PP - MM), mod(PP + MM), mod(ZZ2 + TT2), mod(ZZ2 - TT2));
  }

  subtractAffine(other: AffineCached) {
    const yPlusX = this.y + this.x;
    const yMinusX = this.y - this.x;
    const PP = yPlusX * other.yMinusX;
    const MM = yMinusX * other.yPlusX;
    const TT2 = this.T * other.T2d;
    const ZZ = this.z * this.z;
    const ZZ2 = ZZ + ZZ;
    return new ProjectiveP1xP1(mod(PP - MM), mod(PP + MM), mod(ZZ2 - TT2), mod(ZZ2 + TT2));
  }

  add(other: ProjectiveP3) {
    const cached = ProjectiveCached.fromP3(other);
    const result = this.addCached(cached);
    return ProjectiveP3.fromP1xP1(result);
  }

  subtract(other: ProjectiveP3) {
    const cached = ProjectiveCached.fromP3(other);
    const result = this.subtractCached(cached);
    return ProjectiveP3.fromP1xP1(result);
  }

  double() {
    const x2 = this.x * this.x;
    const y2 = this.y * this.y;
    const z2 = this.z * this.z;
    const xPlusY2 = mod(this.x + this.y) ** 2n;
    const y2PlusX2 = mod(y2 + x2);
    const y2MinusX2 = mod(y2 - x2);
    return new ProjectiveP3(mod(xPlusY2 - y2MinusX2), y2PlusX2, y2MinusX2, mod(z2 - y2MinusX2));
  }

  negative() {
    return new ProjectiveP3(mod(-this.x), this.y, this.z, mod(-this.T));
  }

  multiply(n: bigint) {
    let q = ProjectiveP3.ZERO;
    for (let db: ProjectiveP3 = this; n > 0n; n >>= 1n, db = db.double()) {
      if ((n & 1n) === 1n) {
        q = q.add(db);
      }
    }
    return q;
  }

  // by @ebfull
  // https://github.com/dalek-cryptography/curve25519-dalek/pull/226/files
  equals(other: ProjectiveP3) {
    const t1 = mod(this.x * other.z);
    const t2 = mod(other.x * this.z);
    const t3 = mod(this.y * other.z);
    const t4 = mod(other.y * this.z);
    return t1 === t2 && t3 === t4;
  }
}

export class ProjectiveCached {
  static ZERO() {
    return new ProjectiveCached(1n, 1n, 1n, 0n);
  }

  static fromP3(point: ProjectiveP3) {
    return new ProjectiveCached(
      mod(point.y + point.x),
      mod(point.y - point.x),
      point.z,
      mod(point.T * D2)
    );
  }

  constructor(
    public yPlusX: bigint,
    public yMinusX: bigint,
    public z: bigint,
    public T2d: bigint
  ) {}

  // Select sets v to a if cond == 1 and to b if cond == 0.
  select(other: ProjectiveCached, cond: 0 | 1 | 0n | 1n | boolean) {
    const yPlusX = select(this.yPlusX, other.yPlusX, cond);
    const yMinusX = select(this.yMinusX, other.yMinusX, cond);
    const z = select(this.z, other.z, cond);
    const T2d = select(this.T2d, other.T2d, cond);
    return new ProjectiveCached(yPlusX, yMinusX, z, T2d);
  }

  // Select sets v to a if cond == 1 and to b if cond == 0.
  condNegative(cond: 0 | 1 | 0n | 1n | boolean) {
    const [yPlusX, yMinusX] = condSwap(this.yPlusX, this.yMinusX, cond);
    const T2d = condNegative(this.T2d, cond);
    return new ProjectiveCached(yPlusX, yMinusX, this.z, T2d);
  }
}

export class AffineCached {
  static fromP3(point: ProjectiveP3) {
    const yPlusX = mod(point.y + point.x);
    const yMinusX = mod(point.y - point.x);
    const T2d = point.T * D2;
    const invertedZ = modInverse(point.z);
    const newYPlusX = mod(yPlusX * invertedZ);
    const newYMinusX = mod(yMinusX * invertedZ);
    const newT2D = mod(T2d * invertedZ);
    return new AffineCached(newYPlusX, newYMinusX, newT2D);
  }

  static ZERO() {
    return new AffineCached(1n, 1n, 0n);
  }

  constructor(public yPlusX: bigint, public yMinusX: bigint, public T2d: bigint) {
    this.yPlusX = mod(this.yPlusX);
    this.yMinusX = mod(this.yMinusX);
    this.T2d = mod(this.T2d);
  }

  // Select sets v to a if cond == 1 and to b if cond == 0.
  select(other: AffineCached, cond: 0 | 1 | 0n | 1n | boolean) {
    const yPlusX = select(this.yPlusX, other.yPlusX, cond);
    const yMinusX = select(this.yMinusX, other.yMinusX, cond);
    const T2d = select(this.T2d, other.T2d, cond);
    return new AffineCached(yPlusX, yMinusX, T2d);
  }

  condNegative(cond: 0 | 1 | 0n | 1n | boolean) {
    const [yPlusX, yMinusX] = condSwap(this.yPlusX, this.yMinusX, cond);
    const T2d = condNegative(this.T2d, cond);
    return new AffineCached(yPlusX, yMinusX, T2d);
  }
}

export let sha512: (a: Uint8Array) => Promise<Uint8Array>;

if (typeof window == 'object' && 'crypto' in window) {
  sha512 = async (message: Uint8Array) => {
    const buffer = await window.crypto.subtle.digest('SHA-512', message.buffer);
    return new Uint8Array(buffer);
  };
} else if (typeof process === 'object' && 'node' in process.versions) {
  const { createHash } = require('crypto');
  sha512 = async (message: Uint8Array) => {
    const hash = createHash('sha512');
    hash.update(message);
    return Uint8Array.from(hash.digest());
  };
} else {
  throw new Error("The environment doesn't have sha512 function");
}

function fromHexBE(hex: string) {
  return BigInt(`0x${hex}`);
}

function fromBytesBE(bytes: string | Uint8Array) {
  if (typeof bytes === 'string') {
    return fromHexBE(bytes);
  }
  let value = 0n;
  for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
    value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
  }
  return value;
}

export function fromBytesLE(bytes: Uint8Array) {
  let value = 0n;
  for (let i = 0; i < bytes.length; i++) {
    value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(i));
  }
  return value;
}

export function hexToBytes(hash: string) {
  hash = hash.length & 1 ? `0${hash}` : hash;
  const len = hash.length;
  const result = new Uint8Array(len / 2);
  for (let i = 0, j = 0; i < len - 1; i += 2, j++) {
    result[j] = parseInt(hash[i] + hash[i + 1], 16);
  }
  return result;
}

export function toBigInt(num: string | Uint8Array | bigint | number) {
  if (typeof num === 'string') {
    return fromHexBE(num);
  }
  if (typeof num === 'number') {
    return BigInt(num);
  }
  if (num instanceof Uint8Array) {
    return fromBytesBE(num);
  }
  return num;
}

export function isBytesEquals(b1: Uint8Array, b2: Uint8Array) {
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

export function numberToBytes(num: bigint) {
  let hex = num.toString(16);
  hex = hex.length & 1 ? `0${hex}` : hex;
  const len = hex.length / 2;
  const u8 = new Uint8Array(len);
  for (let j = 0, i = 0; i < hex.length; i += 2, j++) {
    u8[j] = parseInt(hex[i] + hex[i + 1], 16);
  }
  return u8;
}

export function concatTypedArrays(...arrays: Uint8Array[]) {
  const result = new Uint8Array(arrays.reduce((a, arr) => a + arr.length, 0));
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

const ENCODING_LENGTH = 32;

export class RistrettoPoint {
  static ZERO = new RistrettoPoint(ProjectiveP3.ZERO);

  static fromHash(hash: Uint8Array) {
    const r1 = BigInt_fromBytes(hash.slice(0, ENCODING_LENGTH));
    const R1 = this.elligatorRistrettoFlavor(r1);
    const r2 = BigInt_fromBytes(hash.slice(ENCODING_LENGTH, ENCODING_LENGTH * 2));
    const R2 = this.elligatorRistrettoFlavor(r2);
    return new RistrettoPoint(R1.add(R2));
  }

  // Computes the Ristretto Elligator map.
  // This method is not public because it's just used for hashing
  // to a point -- proper elligator support is deferred for now.
  private static elligatorRistrettoFlavor(r0: bigint) {
    const oneMinusDSq = mod(1n - CURVE.d ** 2n);
    const dMinusOneSq = (CURVE.d - 1n) ** 2n;
    const r = SQRT_M1 * (r0 * r0);
    const NS = mod((r + 1n) * oneMinusDSq);
    let c = mod(-1n);
    const D = mod((c - CURVE.d * r) * mod(r + CURVE.d));
    let { isNotZeroSquare, value: S } = sqrtRatio(NS, D);
    let sPrime = S * r0;
    const sPrimeIsPos = !isNegative(sPrime);
    sPrime = condNegative(sPrime, sPrimeIsPos);
    S = select(S, sPrime, isNotZeroSquare);
    c = select(c, r, isNotZeroSquare);
    const NT = c * (r - 1n) * dMinusOneSq - D;
    const sSquared = S * S;
    const projective = new ProjectiveP3(
      mod((S + S) * D),
      mod(1n - sSquared),
      mod(NT * SQRT_AD_MINUS_ONE),
      mod(1n + sSquared)
    );
    return projective.toExtendedCompleted();
  }

  static fromBytes(bytes: Uint8Array) {
    // Step 1. Check s for validity:
    // 1.a) s must be 32 bytes (we get this from the type system)
    // 1.b) s < p
    // 1.c) s is nonnegative
    //
    // Our decoding routine ignores the high bit, so the only
    // possible failure for 1.b) is if someone encodes s in 0..18
    // as s+p in 2^255-19..2^255-1.  We can check this by
    // converting back to bytes, and checking that we get the
    // original input, since our encoding routine is canonical.
    const s = BigInt_fromBytes(bytes);
    const sEncodingIsCanonical = isBytesEquals(toBytesLE(s, ENCODING_LENGTH), bytes);
    const sIsNegative = isNegative(s);
    if (!sEncodingIsCanonical || sIsNegative) {
      throw new Error('Cannot convert bytes to Ristretto Point');
    }
    const s2 = mod(s * s);
    const u1 = mod(1n - s2); // 1 + as²
    const u2 = mod(1n + s2); // 1 - as² where a=-1
    const squaredU2 = mod(u2 * u2); // (1 - as²)²
    // v == ad(1+as²)² - (1-as²)² where d=-121665/121666
    const v = mod(mod(u1 * u1 * -CURVE.d) - squaredU2);
    const { isNotZeroSquare, value: I } = invertSqrt(mod(v * squaredU2)); // 1/sqrt(v*u_2²)
    const Dx = I * u2;
    const Dy = I * Dx * v; // 1/u2
    // x == | 2s/sqrt(v) | == + sqrt(4s²/(ad(1+as²)² - (1-as²)²))
    let x = mod((s + s) * Dx);
    const xIsNegative = BigInt(isNegative(x)) as 0n | 1n;
    x = condNegative(x, xIsNegative);
    // y == (1-as²)/(1+as²)
    const y = mod(u1 * Dy);
    // t == ((1+as²) sqrt(4s²/(ad(1+as²)² - (1-as²)²)))/(1-as²)
    const t = mod(x * y);
    if (!isNotZeroSquare || isNegative(t) || y === 0n) {
      throw new Error('Cannot convert bytes to Ristretto Point');
    }
    return new RistrettoPoint(new ProjectiveP3(x, y, 1n, t));
  }

  constructor(private point: ProjectiveP3) {}

  toBytes() {
    let { x, y, z, T } = this.point;
    // u1 = (z0 + y0) * (z0 - y0)
    const u1 = mod((z + y) * (z - y));
    const u2 = mod(x * y);
    // Ignore return value since this is always square
    const { value: invsqrt } = invertSqrt(mod(u2 ** 2n * u1));
    const i1 = mod(invsqrt * u1);
    const i2 = mod(invsqrt * u2);
    const invertedZ = mod(i1 * i2 * T);
    let invertedDenominator = i2;
    const iX = mod(x * SQRT_M1);
    const iY = mod(y * SQRT_M1);
    const enchantedDenominator = mod(i1 * INVSQRT_A_MINUS_D);
    const isRotated = BigInt(isNegative(T * invertedZ)) as 0n | 1n;
    x = select(iY, x, isRotated);
    y = select(iX, y, isRotated);
    invertedDenominator = select(enchantedDenominator, i2, isRotated);
    const yIsNegative = BigInt(isNegative(x * invertedZ)) as 0n | 1n;
    y = condNegative(y, yIsNegative);
    let s = mod((z - y) * invertedDenominator);
    const sIsNegative = BigInt(isNegative(s)) as 0n | 1n;
    s = condNegative(s, sIsNegative);
    return toBytesLE(s, ENCODING_LENGTH);
  }

  add(other: RistrettoPoint) {
    return new RistrettoPoint(this.point.add(other.point));
  }

  subtract(other: RistrettoPoint) {
    return new RistrettoPoint(this.point.subtract(other.point));
  }

  multiply(n: bigint) {
    return new RistrettoPoint(this.point.multiply(n));
  }

  equals(other: RistrettoPoint) {
    return this.point.equals(other.point);
  }
}

// https://tools.ietf.org/html/rfc8032#section-5.1
export const BASE_POINT = new RistrettoPoint(
  new ProjectiveP3(
    15112221349535400772501151409588531511454012693041857206046113283949847762202n,
    46316835694926478169428394003475163141307993866256225615783033603165251855960n,
    1n,
    46827403850823179245072216630277197565144205554125654976674165829533817101731n
  )
);

// Commented out signature implementation.
// ristretto255 doesn't specify details for ecdsa/eddsa signatures.
// For the future work.

// type PrivateKey = Uint8Array | string | bigint | number;
// type PublicKey = Uint8Array | string | RistrettoPoint;
// type Signature = Uint8Array | string | SignatureResult;
// type Bytes = Uint8Array | string;

// const ENCODING_LENGTH = 32;
// class SignatureResult {
//   constructor(public r: RistrettoPoint, public s: bigint) {}

//   static fromBytes(hex: Bytes) {
//     hex = typeof hex === "string" ? hexToBytes(hex) : hex;
//     const r = RistrettoPoint.fromBytes(hex.slice(0, 32));
//     const s = fromBytesLE(hex.slice(32));
//     return new SignatureResult(r, s);
//   }

//   toBytes() {
//     const sBytes = numberToBytes(this.s).reverse();
//     const rBytes = this.r.toBytes();
//     return concatTypedArrays(rBytes, sBytes);
//   }
// }

// function getPrivateBytes(privateKey: bigint) {
//   return sha512(numberToBytes(privateKey));
// }

// function encodePrivate(privateBytes: Uint8Array) {
//   const last = ENCODING_LENGTH - 1;
//   const head = privateBytes.slice(0, ENCODING_LENGTH);
//   head[0] &= 248;
//   head[last] &= 127;
//   head[last] |= 64;
//   return fromBytesLE(head);
// }

// function normalizeHash(hash: Bytes) {
//   return typeof hash === "string" ? hexToBytes(hash) : hash;
// }

// function normalizePublicKey(publicKey: PublicKey) {
//   if (publicKey instanceof RistrettoPoint) {
//     return publicKey;
//   }
//   publicKey = normalizeHash(publicKey);
//   return RistrettoPoint.fromBytes(publicKey);
// }

// function normalizeSignature(signature: Signature) {
//   if (signature instanceof SignatureResult) {
//     return signature;
//   }
//   signature = normalizeHash(signature);
//   return SignatureResult.fromBytes(signature);
// }

// async function hashNumber(...args: Uint8Array[]) {
//   const messageArray = concatTypedArrays(...args);
//   const hash = await sha512(messageArray);
//   const value = fromBytesLE(hash);
//   return FieldElement.mod(value, PRIME_ORDER);
// }

// export async function getPublicKey(privateKey: PrivateKey, shouldBeRaw = false) {
//   const multiplier = toBigInt(privateKey);
//   const privateBytes = await getPrivateBytes(multiplier);
//   const privateInt = encodePrivate(privateBytes);
//   const publicKey = exports.BASE_POINT.multiply(privateInt);
//   return shouldBeRaw ? publicKey : publicKey.toBytes();
// }

// export async function sign(message: Bytes, privateKey: PrivateKey) {
//   privateKey = toBigInt(privateKey);
//   message = normalizeHash(message);
//   const [publicKey, privateBytes] = await Promise.all([
//     getPublicKey(privateKey, true),
//     getPrivateBytes(privateKey)
//   ]);
//   const privatePrefix = privateBytes.slice(ENCODING_LENGTH);
//   const r = await hashNumber(privatePrefix, message);
//   const R = B.multiply(r);
//   const h = await hashNumber(R.toBytes(), publicKey.toBytes(), message);
//   const S = FieldElement.mod(r + h * encodePrivate(privateBytes), PRIME_ORDER);
//   const signature = new SignatureResult(R, S);
//   return signature.toBytes();
// }

// export async function verify(
//   signature: Signature,
//   message: Bytes,
//   publicKey: PublicKey
// ) {
//   message = normalizeHash(message);
//   publicKey = normalizePublicKey(publicKey);
//   signature = normalizeSignature(signature);
//   const h = await hashNumber(signature.r.toBytes(), publicKey.toBytes(), message);
//   const S = BASE_POINT.multiply(signature.s);
//   const R = signature.r.add(mod(publicKey * h));
//   return S.equals(R);
// }

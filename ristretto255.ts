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

const mask64Bits = (1n << 64n) - 1n;
const low51bitMask = (1n << 51n) - 1n;

export class FieldElement {
  // 𝔽p
  static readonly P = 2n ** 255n - 19n;

  static readonly D = new FieldElement(
    37095705934669439343138083508754565189542113879843219016388785533085940283555n
  );
  // Edwards `2*d` value, equal to `2*(-121665/121666) mod p`.
  static readonly D2 = new FieldElement(
    16295367250680780974490674513165176452449235426866156013048779062215315747161n
  );

  // sqrt(-1 % P)
  static readonly SQRT_M1 = new FieldElement(
    19681161376707505956807079304988542015446066515923890162744021073123829784752n
  );

  // `= 1/sqrt(a-d)`, where `a = -1 (mod p)`, `d` are the Edwards curve parameters.
  static readonly INVSQRT_A_MINUS_D = new FieldElement(
    54469307008909316920995813868745141605393597292927456921205312896311721017578n
  );

  // `= sqrt(a*d - 1)`, where `a = -1 (mod p)`, `d` are the Edwards curve parameters.
  static readonly SQRT_AD_MINUS_ONE = new FieldElement(
    25063068953384623474111414158702152701244531502492656460079210482610430750235n
  );

  // Prime subgroup. 25519 is a curve with cofactor = 8, so the order is:
  static readonly PRIME_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;

  private static load8(input: Uint8Array, padding = 0) {
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

  static fromBytes(bytes: Uint8Array) {
    const octet1 = this.load8(bytes, 0) & low51bitMask;
    const octet2 = (this.load8(bytes, 6) >> 3n) & low51bitMask;
    const octet3 = (this.load8(bytes, 12) >> 6n) & low51bitMask;
    const octet4 = (this.load8(bytes, 19) >> 1n) & low51bitMask;
    const octet5 = (this.load8(bytes, 24) >> 12n) & low51bitMask;
    return new FieldElement(
      octet1 + (octet2 << 51n) + (octet3 << 102n) + (octet4 << 153n) + (octet5 << 204n)
    );
  }

  static one() {
    return new FieldElement(1n);
  }

  static zero() {
    return new FieldElement(0n);
  }

  static mod(a: bigint, b: bigint) {
    const res = a % b;
    return res >= 0 ? res : b + res;
  }

  public readonly value: bigint;

  constructor(value: bigint) {
    this.value = FieldElement.mod(value, FieldElement.P);
  }

  toBytesBE(length: number = 0) {
    let hex = this.value.toString(16);
    hex = hex.length & 1 ? `0${hex}` : hex;
    hex = hex.padStart(length * 2, '0');
    const len = hex.length / 2;
    const u8 = new Uint8Array(len);
    for (let j = 0, i = 0; i < hex.length; i += 2, j++) {
      u8[j] = parseInt(hex[i] + hex[i + 1], 16);
    }
    return u8;
  }

  toBytesLE(length = 0) {
    return this.toBytesBE(length).reverse();
  }

  equals(other: FieldElement) {
    return this.value === other.value;
  }

  isNegative() {
    const bytes = this.toBytesLE();
    return Boolean(bytes[0] & 1);
  }

  isZero() {
    return this.value === 0n;
  }

  add(other: FieldElement) {
    return new FieldElement(this.value + other.value);
  }

  subtract(other: FieldElement) {
    return new FieldElement(this.value - other.value);
  }

  div(other: FieldElement) {
    return new FieldElement(this.value / other.value);
  }

  multiply(other: FieldElement) {
    return new FieldElement(this.value * other.value);
  }

  pow(power: bigint) {
    let res = FieldElement.one();
    let x = this as FieldElement;
    while (power > 0) {
      if (power & 1n) {
        res = res.multiply(x);
      }
      power >>= 1n;
      x = x.square();
    }
    return res;
  }

  pow2k(power: bigint) {
    let res = this as FieldElement;
    while (power-- > 0) {
      res = res.square();
    }
    return res;
  }

  invert() {
    const [t19, t3] = this.pow22501();
    return t19.pow(5n).multiply(t3);
  }

  negative() {
    return new FieldElement(-this.value);
  }

  square() {
    return this.multiply(this);
  }

  private pow22501() {
    const t0 = this.square();
    const t1 = t0.square().square();
    const t2 = this.multiply(t1);
    const t3 = t0.multiply(t2);
    const t4 = t3.square();
    const t5 = t2.multiply(t4);
    const t6 = t5.pow2k(5n);
    const t7 = t6.multiply(t5);
    const t8 = t7.pow2k(10n);
    const t9 = t8.multiply(t7);
    const t10 = t9.pow2k(20n);
    const t11 = t10.multiply(t9);
    const t12 = t11.pow2k(10n);
    const t13 = t12.multiply(t7);
    const t14 = t13.pow2k(50n);
    const t15 = t14.multiply(t13);
    const t16 = t15.pow2k(100n);
    const t17 = t16.multiply(t15);
    const t18 = t17.pow2k(50n);
    const t19 = t18.multiply(t13);
    return [t19, t3];
  }

  private powP58() {
    const [t19] = this.pow22501();
    return t19.pow2k(2n).multiply(this);
  }

  // Select sets v to a if cond == 1, and to b if cond == 0.
  select(other: FieldElement, choice: 0n | 1n | 0 | 1 | boolean) {
    return choice ? this : other;
  }

  condNegative(choice: 0n | 1n | 0 | 1 | boolean) {
    return this.negative().select(this, choice);
  }

  // CondSwap swaps a and b if cond == 1 or leaves them unchanged if cond == 0.
  condSwap(other: FieldElement, choice: 0n | 1n | 0 | 1 | boolean) {
    choice = BigInt(choice) as 0n | 1n;
    const mask = choice !== 0n ? mask64Bits : choice;
    const tmp = mask & (this.value ^ other.value);
    return [new FieldElement(this.value ^ tmp), new FieldElement(other.value ^ tmp)];
  }

  sqrtRatio(v: FieldElement) {
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
    const v3 = v.multiply(v).multiply(v);
    const v7 = v3.multiply(v3).multiply(v);
    let r = this.multiply(v7)
      .powP58()
      .multiply(this)
      .multiply(v3);
    const check = r.square().multiply(v);
    const i = FieldElement.SQRT_M1;
    const correctSignSqrt = check.equals(this);
    const flippedSignSqrt = check.equals(this.negative());
    const flippedSignSqrtI = check.equals(this.negative().multiply(i));
    const rPrime = FieldElement.SQRT_M1.multiply(r);
    r = rPrime.select(r, flippedSignSqrt || flippedSignSqrtI);
    r = r.condNegative(r.isNegative());
    const isNotZeroSquare = correctSignSqrt || flippedSignSqrt;
    return { isNotZeroSquare, value: r };
  }

  // Attempt to compute `sqrt(1/self)` in constant time.
  invertSqrt() {
    return FieldElement.one().sqrtRatio(this);
  }
}

export const P = FieldElement.P;
export const PRIME_ORDER = FieldElement.PRIME_ORDER;

export class ProjectiveP1xP1 {
  static zero() {
    return new ProjectiveP1xP1(
      FieldElement.zero(),
      FieldElement.one(),
      FieldElement.one(),
      FieldElement.one()
    );
  }

  constructor(
    public x: FieldElement,
    public y: FieldElement,
    public z: FieldElement,
    public T: FieldElement
  ) {}
}

export class ProjectiveP2 {
  static fromP1xP1(point: ProjectiveP1xP1) {
    return new ProjectiveP2(
      point.x.multiply(point.T),
      point.y.multiply(point.T),
      point.z.multiply(point.T)
    );
  }

  static fromP3(point: ProjectiveP3) {
    return new ProjectiveP2(point.x, point.y, point.z);
  }

  static zero() {
    return new ProjectiveP2(FieldElement.zero(), FieldElement.one(), FieldElement.one());
  }

  constructor(public x: FieldElement, public y: FieldElement, public z: FieldElement) {}

  double() {
    const squaredX = this.x.square();
    const squaredY = this.y.square();
    const squaredZ = this.z.square();
    const squaredZ2 = squaredZ.add(squaredZ);
    const xPlusYSquared = this.x.add(this.y).square();
    const y = squaredY.add(squaredX);
    const z = squaredY.subtract(squaredX);
    const x = xPlusYSquared.subtract(y);
    const T = squaredZ2.subtract(this.z);
    return new ProjectiveP1xP1(x, y, z, T);
  }
}

export class ProjectiveP3 {
  static fromP1xP1(point: ProjectiveP1xP1) {
    return new ProjectiveP3(
      point.x.multiply(point.T),
      point.y.multiply(point.z),
      point.z.multiply(point.T),
      point.x.multiply(point.y)
    );
  }

  static fromP2(point: ProjectiveP2) {
    return new ProjectiveP3(
      point.x.multiply(point.z),
      point.y.multiply(point.z),
      point.z.square(),
      point.x.multiply(point.y)
    );
  }

  static one() {
    return new ProjectiveP3(
      FieldElement.zero(),
      FieldElement.one(),
      FieldElement.one(),
      FieldElement.zero()
    );
  }

  constructor(
    public x: FieldElement,
    public y: FieldElement,
    public z: FieldElement,
    public T: FieldElement
  ) {}

  toProjectiveNielsPoint() {
    return new ProjectiveP3(
      this.y.add(this.x),
      this.y.subtract(this.x),
      this.z,
      this.T.multiply(FieldElement.D2)
    );
  }

  toExtendedProjective() {
    return new ProjectiveP3(
      this.x.multiply(this.z),
      this.y.multiply(this.z),
      this.z.multiply(this.z),
      this.x.multiply(this.y)
    );
  }

  toExtendedCompleted() {
    return new ProjectiveP3(
      this.x.multiply(this.T),
      this.y.multiply(this.z),
      this.z.multiply(this.T),
      this.x.multiply(this.y)
    );
  }

  addCached(other: ProjectiveCached) {
    const yPlusX = this.y.add(this.x);
    const yMinusX = this.y.subtract(this.x);
    const PP = yPlusX.multiply(other.yPlusX);
    const MM = yMinusX.multiply(other.yMinusX);
    const TT2 = this.T.multiply(other.T2d);
    const ZZ = this.z.multiply(other.z);
    const ZZ2 = ZZ.add(ZZ);
    return new ProjectiveP1xP1(PP.subtract(MM), PP.add(MM), ZZ2.add(TT2), ZZ2.subtract(TT2));
  }

  subtractCached(other: ProjectiveCached) {
    const yPlusX = this.y.add(this.x);
    const yMinusX = this.y.subtract(this.x);
    const PP = yPlusX.multiply(other.yMinusX);
    const MM = yMinusX.multiply(other.yPlusX);
    const TT2 = this.T.multiply(other.T2d);
    const ZZ = this.z.multiply(other.z);
    const ZZ2 = ZZ.add(ZZ);
    return new ProjectiveP1xP1(PP.subtract(MM), PP.add(MM), ZZ2.subtract(TT2), ZZ2.add(TT2));
  }

  addAffine(other: AffineCached) {
    const yPlusX = this.y.add(this.x);
    const yMinusX = this.y.subtract(this.x);
    const PP = yPlusX.multiply(other.yPlusX);
    const MM = yMinusX.multiply(other.yMinusX);
    const TT2 = this.T.multiply(other.T2d);
    const ZZ = this.z.multiply(this.z);
    const ZZ2 = ZZ.add(ZZ);
    return new ProjectiveP1xP1(PP.subtract(MM), PP.add(MM), ZZ2.add(TT2), ZZ2.subtract(TT2));
  }

  subtractAffine(other: AffineCached) {
    const yPlusX = this.y.add(this.x);
    const yMinusX = this.y.subtract(this.x);
    const PP = yPlusX.multiply(other.yMinusX);
    const MM = yMinusX.multiply(other.yPlusX);
    const TT2 = this.T.multiply(other.T2d);
    const ZZ = this.z.multiply(this.z);
    const ZZ2 = ZZ.add(ZZ);
    return new ProjectiveP1xP1(PP.subtract(MM), PP.add(MM), ZZ2.subtract(TT2), ZZ2.add(TT2));
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
    const x2 = this.x.square();
    const y2 = this.y.square();
    const z2 = this.z.square();
    const xPlusY2 = this.x.add(this.y).square();
    const y2PlusX2 = y2.add(x2);
    const y2MinusX2 = y2.subtract(x2);
    return new ProjectiveP3(
      xPlusY2.subtract(y2MinusX2),
      y2PlusX2,
      y2MinusX2,
      z2.subtract(y2MinusX2)
    );
  }

  negative() {
    return new ProjectiveP3(this.x.negative(), this.y, this.z, this.T.negative());
  }

  multiply(n: bigint) {
    let q = ProjectiveP3.one();
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
    const t1 = this.x.multiply(other.z);
    const t2 = other.x.multiply(this.z);
    const t3 = this.y.multiply(other.z);
    const t4 = other.y.multiply(this.z);
    return t1.equals(t2) && t3.equals(t4);
  }
}

export class ProjectiveCached {
  static one() {
    return new ProjectiveCached(
      FieldElement.one(),
      FieldElement.one(),
      FieldElement.one(),
      FieldElement.zero()
    );
  }

  static fromP3(point: ProjectiveP3) {
    return new ProjectiveCached(
      point.y.add(point.x),
      point.y.subtract(point.x),
      point.z,
      point.T.multiply(FieldElement.D2)
    );
  }

  constructor(
    public yPlusX: FieldElement,
    public yMinusX: FieldElement,
    public z: FieldElement,
    public T2d: FieldElement
  ) {}

  // Select sets v to a if cond == 1 and to b if cond == 0.
  select(other: ProjectiveCached, cond: 0 | 1 | 0n | 1n | boolean) {
    const yPlusX = this.yPlusX.select(other.yPlusX, cond);
    const yMinusX = this.yMinusX.select(other.yMinusX, cond);
    const z = this.z.select(other.z, cond);
    const T2d = this.T2d.select(other.T2d, cond);
    return new ProjectiveCached(yPlusX, yMinusX, z, T2d);
  }

  // Select sets v to a if cond == 1 and to b if cond == 0.
  condNegative(cond: 0 | 1 | 0n | 1n | boolean) {
    const [yPlusX, yMinusX] = this.yPlusX.condSwap(this.yMinusX, cond);
    const T2d = this.T2d.condNegative(cond);
    return new ProjectiveCached(yPlusX, yMinusX, this.z, T2d);
  }
}

export class AffineCached {
  static fromP3(point: ProjectiveP3) {
    const yPlusX = point.y.add(point.x);
    const yMinusX = point.y.subtract(point.x);
    const T2d = point.T.multiply(FieldElement.D2);
    const invertedZ = point.z.invert();
    const newYPlusX = yPlusX.multiply(invertedZ);
    const newYMinusX = yMinusX.multiply(invertedZ);
    const newT2D = T2d.multiply(invertedZ);
    return new AffineCached(newYPlusX, newYMinusX, newT2D);
  }

  static one() {
    return new AffineCached(FieldElement.one(), FieldElement.one(), FieldElement.zero());
  }

  constructor(
    public yPlusX: FieldElement,
    public yMinusX: FieldElement,
    public T2d: FieldElement
  ) {}

  // Select sets v to a if cond == 1 and to b if cond == 0.
  select(other: AffineCached, cond: 0 | 1 | 0n | 1n | boolean) {
    const yPlusX = this.yPlusX.select(other.yPlusX, cond);
    const yMinusX = this.yMinusX.select(other.yMinusX, cond);
    const T2d = this.T2d.select(other.T2d, cond);
    return new AffineCached(yPlusX, yMinusX, T2d);
  }

  condNegative(cond: 0 | 1 | 0n | 1n | boolean) {
    const [yPlusX, yMinusX] = this.yPlusX.condSwap(this.yMinusX, cond);
    const T2d = this.T2d.condNegative(cond);
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

export function concatTypedArrays(...args: Uint8Array[]) {
  const result = new Uint8Array(args.reduce((a, arr) => a + arr.length, 0));
  for (let i = 0, pad = 0; i < args.length; i++) {
    const arr = args[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

const ENCODING_LENGTH = 32;

export class RistrettoPoint {
  static one() {
    return new RistrettoPoint(ProjectiveP3.one());
  }

  static fromHash(hash: Uint8Array) {
    const r1 = FieldElement.fromBytes(hash.slice(0, ENCODING_LENGTH));
    const R1 = this.elligatorRistrettoFlavor(r1);
    const r2 = FieldElement.fromBytes(hash.slice(ENCODING_LENGTH, ENCODING_LENGTH * 2));
    const R2 = this.elligatorRistrettoFlavor(r2);
    return new RistrettoPoint(R1.add(R2));
  }

  // Computes the Ristretto Elligator map.
  // This method is not public because it's just used for hashing
  // to a point -- proper elligator support is deferred for now.
  private static elligatorRistrettoFlavor(r0: FieldElement) {
    const one = FieldElement.one();
    const oneMinusDSq = one.subtract(FieldElement.D.square());
    const dMinusOneSq = FieldElement.D.subtract(one).square();
    const r = FieldElement.SQRT_M1.multiply(r0.square());
    const NS = r.add(one).multiply(oneMinusDSq);
    let c = one.negative();
    const D = c.subtract(FieldElement.D.multiply(r)).multiply(r.add(FieldElement.D));
    let { isNotZeroSquare, value: S } = NS.sqrtRatio(D);
    let sPrime = S.multiply(r0);
    const sPrimeIsPos = !sPrime.isNegative();
    sPrime = sPrime.condNegative(sPrimeIsPos);
    S = S.select(sPrime, isNotZeroSquare);
    c = c.select(r, isNotZeroSquare);
    const NT = c
      .multiply(r.subtract(one))
      .multiply(dMinusOneSq)
      .subtract(D);
    const sSquared = S.square();
    const projective = new ProjectiveP3(
      S.add(S).multiply(D),
      FieldElement.one().subtract(sSquared),
      NT.multiply(FieldElement.SQRT_AD_MINUS_ONE),
      FieldElement.one().add(sSquared)
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
    const s = FieldElement.fromBytes(bytes);
    const sEncodingIsCanonical = isBytesEquals(s.toBytesLE(ENCODING_LENGTH), bytes);
    const sIsNegative = s.isNegative();
    if (!sEncodingIsCanonical || sIsNegative) {
      throw new Error('Cannot convert bytes to Ristretto Point');
    }
    const one = FieldElement.one();
    const s2 = s.square();
    const u1 = one.subtract(s2); // 1 + as²
    const u2 = one.add(s2); // 1 - as² where a=-1
    const squaredU2 = u2.square(); // (1 - as²)²
    // v == ad(1+as²)² - (1-as²)² where d=-121665/121666
    const v = u1
      .square()
      .multiply(FieldElement.D.negative())
      .subtract(squaredU2);
    const { isNotZeroSquare, value: I } = v.multiply(squaredU2).invertSqrt(); // 1/sqrt(v*u_2²)
    const Dx = I.multiply(u2);
    const Dy = I.multiply(Dx).multiply(v); // 1/u2
    // x == | 2s/sqrt(v) | == + sqrt(4s²/(ad(1+as²)² - (1-as²)²))
    let x = s.add(s).multiply(Dx);
    const xIsNegative = BigInt(x.isNegative()) as 0n | 1n;
    x = x.condNegative(xIsNegative);
    // y == (1-as²)/(1+as²)
    const y = u1.multiply(Dy);
    // t == ((1+as²) sqrt(4s²/(ad(1+as²)² - (1-as²)²)))/(1-as²)
    const t = x.multiply(y);
    if (!isNotZeroSquare || t.isNegative() || y.isZero()) {
      throw new Error('Cannot convert bytes to Ristretto Point');
    }
    return new RistrettoPoint(new ProjectiveP3(x, y, one, t));
  }

  constructor(private point: ProjectiveP3) {}

  toBytes() {
    let { x, y, z, T } = this.point;
    // u1 = (z0 + y0) * (z0 - y0)
    const u1 = z.add(y).multiply(z.subtract(y));
    const u2 = x.multiply(y);
    // Ignore return value since this is always square
    const { value: invsqrt } = u2
      .square()
      .multiply(u1)
      .invertSqrt();
    const i1 = invsqrt.multiply(u1);
    const i2 = invsqrt.multiply(u2);
    const invertedZ = i1.multiply(i2).multiply(T);
    let invertedDenominator = i2;
    const iX = x.multiply(FieldElement.SQRT_M1);
    const iY = y.multiply(FieldElement.SQRT_M1);
    const enchantedDenominator = i1.multiply(FieldElement.INVSQRT_A_MINUS_D);
    const isRotated = BigInt(T.multiply(invertedZ).isNegative()) as 0n | 1n;
    x = iY.select(x, isRotated);
    y = iX.select(y, isRotated);
    invertedDenominator = enchantedDenominator.select(i2, isRotated);
    const yIsNegative = BigInt(x.multiply(invertedZ).isNegative()) as 0n | 1n;
    y = y.condNegative(yIsNegative);
    let s = z.subtract(y).multiply(invertedDenominator);
    const sIsNegative = BigInt(s.isNegative()) as 0n | 1n;
    s = s.condNegative(sIsNegative);
    return s.toBytesLE(ENCODING_LENGTH);
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
    new FieldElement(
      15112221349535400772501151409588531511454012693041857206046113283949847762202n
    ),
    new FieldElement(
      46316835694926478169428394003475163141307993866256225615783033603165251855960n
    ),
    new FieldElement(1n),
    new FieldElement(46827403850823179245072216630277197565144205554125654976674165829533817101731n)
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
//   const R = signature.r.add(publicKey.multiply(h));
//   return S.equals(R);
// }

/*! noble-ed25519 - MIT License (c) Paul Miller (paulmillr.com) */
// https://ed25519.cr.yp.to
// https://tools.ietf.org/html/rfc8032
// https://en.wikipedia.org/wiki/EdDSA
// Thanks DJB!

export const CURVE_PARAMS = {
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

type PrivKey = Uint8Array | string | bigint | number;
type PubKey = Uint8Array | string | Point;
type Hex = Uint8Array | string;
type Signature = Uint8Array | string | SignResult;

const ENCODING_LENGTH = 32;
const P = CURVE_PARAMS.P;
const PRIME_ORDER = CURVE_PARAMS.n;
const I = powMod(2n, (P - 1n) / 4n, P);

export class Point {
  // Base point aka generator
  // public_key = base_point * private_key
  static BASE_POINT: Point = new Point(CURVE_PARAMS.Gx, CURVE_PARAMS.Gy);
  // Identity point aka point at infinity
  // point = point + zero_point
  static ZERO_POINT: Point = new Point(0n, 1n);

  WINDOW_SIZE?: number;
  private PRECOMPUTES?: Point[];

  constructor(public x: bigint, public y: bigint) {}

  static fromHex(hash: Hex) {
    const {a, d} = CURVE_PARAMS;

    // rfc8032 5.1.3
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
    if (mod(x * x - sqrX, P) !== 0n) {
      x = mod(x * I, P);
    }
    const isXOdd = (x & 1n) === 1n;
    if (isLastByteOdd !== isXOdd) {
      x = mod(-x, P);
    }
    return new Point(x, y);
  }

  encode(): Uint8Array {
    let hex = this.y.toString(16);
    hex = hex.length & 1 ? `0${hex}` : hex;
    const u8 = new Uint8Array(ENCODING_LENGTH);
    for (let i = hex.length - 2, j = 0; j < ENCODING_LENGTH && i >= 0; i -= 2, j++) {
      u8[j] = parseInt(hex[i] + hex[i + 1], 16);
    }
    const mask = this.x & 1n ? 0x80 : 0;
    u8[ENCODING_LENGTH - 1] |= mask;
    return u8;
  }

  /**
   * Converts point to compressed representation of its Y.
   * ECDSA uses `04${x}${y}` to represent long form and
   * `02${x}` / `03${x}` to represent short form,
   * where leading bit signifies positive or negative Y.
   * EDDSA (ed25519) uses short form.
   */
  toHex(): string {
    const bytes = this.encode();
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      const value = bytes[i].toString(16);
      hex = `${hex}${value.length > 1 ? value : `0${value}`}`;
    }
    return hex;
  }

  // Converts to Montgomery; aka x coordinate of curve25519.
  // We don't have fromX25519, because we don't know sign!
  toX25519() {
    // curve25519 is birationally equivalent to ed25519
    // x, y: ed25519 coordinates
    // u, v: x25519 coordinates
    // u = (1 + y) / (1 - y)
    // See https://blog.filippo.io/using-ed25519-keys-for-encryption
    const res = (1n + this.y) * modInverse(1n - this.y);
    return mod(res, P);
  }

  negate(): Point {
    return new Point(this.x, mod(-this.y, P));
  }

  add(other: Point): Point {
    if (!(other instanceof Point)) {
      throw new TypeError('Point#add: expected Point');
    }
    const {d} = CURVE_PARAMS;
    const a = this;
    const b = other;
    const x = (a.x * b.y + b.x * a.y) * modInverse(1n + d * a.x * b.x * a.y * b.y);
    const y = (a.y * b.y + a.x * b.x) * modInverse(1n - d * a.x * b.x * a.y * b.y);
    return new Point(mod(x, P), mod(y, P));
  }

  subtract(other: Point) {
    return this.add(other.negate());
  }

  private precomputeWindow(W: number): Point[] {
    if (this.PRECOMPUTES) return this.PRECOMPUTES;
    const points: Point[] = new Array((2 ** W - 1) * W);
    if (W !== 1) {
      this.PRECOMPUTES = points;
    }
    let currPoint: Point = this;
    const winSize = 2 ** W - 1;
    for (let currWin = 0; currWin < 256 / W; currWin++) {
      let offset = currWin * winSize;
      let point: Point = currPoint;
      for (let i = 0; i < winSize; i++) {
        points[offset + i] = point;
        point = point.add(currPoint);
      }
      currPoint = point;
    }
    return points;
  }

  // Constant time multiplication.
  // No need to emulate constant-time in ed25519 with `f` fake point,
  // there is no special case for Point#add(0); private keys are hashed.
  multiply(scalar: number | bigint): Point {
    if (typeof scalar !== 'number' && typeof scalar !== 'bigint') {
      throw new TypeError('Point#multiply: expected number or bigint');
    }
    let n = mod(BigInt(scalar), PRIME_ORDER);
    if (n <= 0) {
      throw new Error('Point#multiply: invalid scalar, expected positive integer');
    }
    const W = this.WINDOW_SIZE || 1;
    if (256 % W) {
      throw new Error('Point#multiply: Invalid precomputation window, must be power of 2');
    }
    const precomputes = this.precomputeWindow(W);
    let p = Point.ZERO_POINT;
    // let f = ZERO_POINT;
    const winSize = 2 ** W - 1;
    for (let currWin = 0; currWin < 256 / W; currWin++) {
      const offset = currWin * winSize;
      const masked = Number(n & BigInt(winSize));
      if (masked) {
        p = p.add(precomputes[offset + masked - 1]);
      } else {
        // f = f.add(precomputes[offset]);
      }
      n >>= BigInt(W);
    }
    return p;
  }
}

export class SignResult {
  constructor(public r: Point, public s: bigint) {}

  static fromHex(hex: Hex) {
    hex = normalizeHash(hex);
    const r = Point.fromHex(hex.slice(0, 32));
    const s = arrayToNumberLE(hex.slice(32));
    return new SignResult(r, s);
  }

  toHex() {
    const numberBytes = numberToUint8Array(this.s).reverse();
    const sBytes = new Uint8Array(ENCODING_LENGTH);
    sBytes.set(numberBytes);
    const bytes = concatTypedArrays(this.r.encode(), sBytes);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      const value = bytes[i].toString(16);
      hex = `${hex}${value.length > 1 ? value : `0${value}`}`;
    }
    return hex;
  }
}

let sha512: (message: Uint8Array) => Promise<Uint8Array>;

if (typeof window == 'object' && 'crypto' in window) {
  sha512 = async (message: Uint8Array) => {
    const buffer = await window.crypto.subtle.digest('SHA-512', message.buffer);
    return new Uint8Array(buffer);
  };
} else if (typeof process === 'object' && 'node' in process.versions) {
  const req = require;
  const { createHash } = req('crypto');
  sha512 = async (message: Uint8Array) => {
    const hash = createHash('sha512');
    hash.update(message);
    return Uint8Array.from(hash.digest());
  };
} else {
  throw new Error("The environment doesn't have sha512 function");
}

function concatTypedArrays(...args: Array<Uint8Array>): Uint8Array {
  const result = new Uint8Array(args.reduce((a, arr) => a + arr.length, 0));
  for (let i = 0, pad = 0; i < args.length; i++) {
    const arr = args[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

function numberToUint8Array(num: bigint | number, padding?: number): Uint8Array {
  let hex = num.toString(16);
  if (padding) hex = hex.padStart(padding);
  hex = hex.length & 1 ? `0${hex}` : hex;
  const len = hex.length / 2;
  const u8 = new Uint8Array(len);
  for (let j = 0, i = 0; i < hex.length; i += 2, j++) {
    u8[j] = parseInt(hex[i] + hex[i + 1], 16);
  }
  return u8;
}

function arrayToNumberLE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = 0; i < bytes.length; i++) {
    value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(i));
  }
  return value;
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

function hexToArray(hash: string): Uint8Array {
  hash = hash.length & 1 ? `0${hash}` : hash;
  const len = hash.length;
  const result = new Uint8Array(len / 2);
  for (let i = 0, j = 0; i < len - 1; i += 2, j++) {
    result[j] = parseInt(hash[i] + hash[i + 1], 16);
  }
  return result;
}

function hexToNumber(hex: string) {
  return BigInt(`0x${hex}`);
}

function arrayToNumberBE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
    value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
  }
  return value;
}

async function hashNumber(...args: Array<Uint8Array>) {
  const messageArray = concatTypedArrays(...args);
  const hash = await sha512(messageArray);
  const value = arrayToNumberLE(hash);
  return mod(value, PRIME_ORDER);
}

function getPrivateBytes(privateKey: bigint | number | Uint8Array) {
  return sha512(privateKey instanceof Uint8Array ? privateKey : numberToUint8Array(privateKey, 64));
}

function keyPrefix(privateBytes: Uint8Array) {
  return privateBytes.slice(ENCODING_LENGTH);
}

function mod(a: bigint, b: bigint) {
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

function encodePrivate(privateBytes: Uint8Array) {
  const last = ENCODING_LENGTH - 1;
  const head = privateBytes.slice(0, ENCODING_LENGTH);
  head[0] &= 248;
  head[last] &= 127;
  head[last] |= 64;

  return arrayToNumberLE(head);
}

function normalizePrivateKey(privateKey: PrivKey): bigint {
  let res: bigint;
  if (privateKey instanceof Uint8Array) {
    res = arrayToNumberBE(privateKey);
  } else if (typeof privateKey === 'string') {
    res = hexToNumber(privateKey);
  } else {
    res = BigInt(privateKey);
  }
  return res;
}

function normalizePublicKey(publicKey: PubKey): Point {
  return publicKey instanceof Point ? publicKey : Point.fromHex(publicKey);
}

function normalizePoint(point: Point, privateKey: PrivKey): Uint8Array | string | Point {
  if (privateKey instanceof Uint8Array) {
    return point.encode();
  }
  if (typeof privateKey === 'string') {
    return point.toHex();
  }
  return point;
}

function normalizeSignature(signature: Signature): SignResult {
  return signature instanceof SignResult ? signature : SignResult.fromHex(signature);
}

function normalizeHash(hash: Hex) {
  return hash instanceof Uint8Array ? hash : hexToArray(hash);
}

export function getPublicKey(privateKey: Uint8Array): Promise<Uint8Array>;
export function getPublicKey(privateKey: string): Promise<string>;
export function getPublicKey(privateKey: bigint | number): Promise<Point>;
export async function getPublicKey(privateKey: PrivKey) {
  const multiplier = normalizePrivateKey(privateKey);
  const privateBytes = await getPrivateBytes(multiplier);
  const privateInt = encodePrivate(privateBytes);
  const publicKey = Point.BASE_POINT.multiply(privateInt);
  const p = normalizePoint(publicKey, privateKey);
  return p;
}

export function sign(hash: Uint8Array, privateKey: PrivKey): Promise<Uint8Array>;
export function sign(hash: string, privateKey: PrivKey): Promise<string>;
export async function sign(hash: Hex, privateKey: PrivKey) {
  const message = normalizeHash(hash);
  privateKey = normalizePrivateKey(privateKey);
  const publicKey = await getPublicKey(privateKey);
  const privateBytes = await getPrivateBytes(privateKey);
  const privatePrefix = keyPrefix(privateBytes);
  const r = await hashNumber(privatePrefix, message);
  const R = Point.BASE_POINT.multiply(r);
  const h = await hashNumber(R.encode(), publicKey.encode(), message);
  const S = mod(r + h * encodePrivate(privateBytes), PRIME_ORDER);
  const signature = new SignResult(R, S).toHex();
  return hash instanceof Uint8Array ? hexToArray(signature) : signature;
}

export async function verify(signature: Signature, hash: Hex, publicKey: PubKey) {
  hash = normalizeHash(hash);
  publicKey = normalizePublicKey(publicKey);
  signature = normalizeSignature(signature);
  const h = await hashNumber(signature.r.encode(), publicKey.encode(), hash);
  const S = Point.BASE_POINT.multiply(signature.s);
  const R = signature.r.add(publicKey.multiply(h));
  return S.x === R.x && S.y === R.y;
}

// Enable precomputes. Slows down first publicKey computation by 500ms.
Point.BASE_POINT.WINDOW_SIZE = 4;

export const utils = {
  precompute(windowSize = 4, point = Point.BASE_POINT): true {
    point.WINDOW_SIZE = windowSize;
    point.multiply(1n);
    return true;
  }
};

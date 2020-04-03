"use strict";
/*! noble-ed25519 - MIT License (c) Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
exports.CURVE_PARAMS = {
    a: -1n,
    d: 37095705934669439343138083508754565189542113879843219016388785533085940283555n,
    P: 2n ** 255n - 19n,
    n: 2n ** 252n + 27742317777372353535851937790883648493n,
    h: 8n,
    Gx: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
    Gy: 46316835694926478169428394003475163141307993866256225615783033603165251855960n
};
const ENCODING_LENGTH = 32;
const P = exports.CURVE_PARAMS.P;
const PRIME_ORDER = exports.CURVE_PARAMS.n;
const I = powMod(2n, (P - 1n) / 4n, P);
class ExtendedPoint {
    constructor(x, y, z, t) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.t = t;
    }
    static fromAffine(p) {
        if (p.equals(Point.ZERO_POINT))
            return ExtendedPoint.ZERO_POINT;
        return new ExtendedPoint(p.x, p.y, 1n, mod(p.x * p.y));
    }
    static batchAffine(points) {
        const toInv = batchInverse(points.map(p => p.z));
        return points.map((p, i) => p.toAffine(toInv[i]));
    }
    equals(other) {
        const a = this;
        const b = other;
        const [T1, T2, Z1, Z2] = [a.t, b.t, a.z, b.z];
        return mod(T1 * Z2) === mod(T2 * Z1);
    }
    negate() {
        return new ExtendedPoint(mod(-this.x), this.y, this.z, mod(-this.t));
    }
    double() {
        const _a = this;
        const X1 = _a.x, Y1 = _a.y, Z1 = _a.z;
        const { a } = exports.CURVE_PARAMS;
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
    add(other) {
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
    multiplyUnsafe(scalar) {
        if (typeof scalar !== 'number' && typeof scalar !== 'bigint') {
            throw new TypeError('Point#multiply: expected number or bigint');
        }
        let n = mod(BigInt(scalar), PRIME_ORDER);
        if (n <= 0) {
            throw new Error('Point#multiply: invalid scalar, expected positive integer');
        }
        let p = ExtendedPoint.ZERO_POINT;
        let d = this;
        while (n > 0n) {
            if (n & 1n)
                p = p.add(d);
            d = d.double();
            n >>= 1n;
        }
        return p;
    }
    toAffine(invZ = modInverse(this.z)) {
        const x = mod(this.x * invZ);
        const y = mod(this.y * invZ);
        return new Point(x, y);
    }
}
ExtendedPoint.ZERO_POINT = new ExtendedPoint(0n, 1n, 1n, 0n);
const pointPrecomputes = new WeakMap();
class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }
    _setWindowSize(windowSize) {
        this.WINDOW_SIZE = windowSize;
        pointPrecomputes.delete(this);
    }
    static fromHex(hash) {
        const { d } = exports.CURVE_PARAMS;
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
    toRawBytes() {
        const hex = numberToHex(this.y);
        const u8 = new Uint8Array(ENCODING_LENGTH);
        for (let i = hex.length - 2, j = 0; j < ENCODING_LENGTH && i >= 0; i -= 2, j++) {
            u8[j] = parseInt(hex[i] + hex[i + 1], 16);
        }
        const mask = this.x & 1n ? 0x80 : 0;
        u8[ENCODING_LENGTH - 1] |= mask;
        return u8;
    }
    toHex() {
        return arrayToHex(this.toRawBytes());
    }
    toX25519() {
        return mod((1n + this.y) * modInverse(1n - this.y));
    }
    equals(other) {
        return this.x === other.x && this.y === other.y;
    }
    negate() {
        return new Point(this.x, mod(-this.y));
    }
    add(other) {
        if (!(other instanceof Point)) {
            throw new TypeError('Point#add: expected Point');
        }
        const { d } = exports.CURVE_PARAMS;
        const X1 = this.x;
        const Y1 = this.y;
        const X2 = other.x;
        const Y2 = other.y;
        const X3 = (X1 * Y2 + Y1 * X2) * modInverse(1n + d * X1 * X2 * Y1 * Y2);
        const Y3 = (Y1 * Y2 + X1 * X2) * modInverse(1n - d * X1 * X2 * Y1 * Y2);
        return new Point(mod(X3), mod(Y3));
    }
    subtract(other) {
        return this.add(other.negate());
    }
    precomputeWindow(W) {
        const cached = pointPrecomputes.get(this);
        if (cached)
            return cached;
        const windows = 256 / W + 1;
        let points = [];
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
    wNAF(n, isHalf = false) {
        const W = this.WINDOW_SIZE || 1;
        if (256 % W) {
            throw new Error('Point#multiply: Invalid precomputation window, must be power of 2');
        }
        const precomputes = this.precomputeWindow(W);
        let p = ExtendedPoint.ZERO_POINT;
        let f = ExtendedPoint.ZERO_POINT;
        const windows = 256 / W + 1;
        const windowSize = 2 ** (W - 1);
        const mask = BigInt(2 ** W - 1);
        const maxNumber = 2 ** W;
        const shiftBy = BigInt(W);
        for (let window = 0; window < windows; window++) {
            const offset = window * windowSize;
            let wbits = Number(n & mask);
            n >>= shiftBy;
            if (wbits > windowSize) {
                wbits -= maxNumber;
                n += 1n;
            }
            if (wbits === 0) {
                f = f.add(precomputes[offset]);
            }
            else {
                const cached = precomputes[offset + Math.abs(wbits) - 1];
                p = p.add(wbits < 0 ? cached.negate() : cached);
            }
        }
        return [p, f];
    }
    multiply(scalar, isAffine = true) {
        if (typeof scalar !== 'number' && typeof scalar !== 'bigint') {
            throw new TypeError('Point#multiply: expected number or bigint');
        }
        let n = mod(BigInt(scalar), PRIME_ORDER);
        if (n <= 0) {
            throw new Error('Point#multiply: invalid scalar, expected positive integer');
        }
        let point;
        let fake;
        [point, fake] = this.wNAF(n);
        return isAffine ? ExtendedPoint.batchAffine([point, fake])[0] : point;
    }
}
exports.Point = Point;
Point.BASE_POINT = new Point(exports.CURVE_PARAMS.Gx, exports.CURVE_PARAMS.Gy);
Point.ZERO_POINT = new Point(0n, 1n);
const { BASE_POINT } = Point;
class SignResult {
    constructor(r, s) {
        this.r = r;
        this.s = s;
    }
    static fromHex(hex) {
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
    }
    toHex() {
        return arrayToHex(this.toRawBytes());
    }
}
exports.SignResult = SignResult;
let sha512;
let generateRandomPrivateKey = (bytesLength = 32) => new Uint8Array(0);
if (typeof window == 'object' && 'crypto' in window) {
    sha512 = async (message) => {
        const buffer = await window.crypto.subtle.digest('SHA-512', message.buffer);
        return new Uint8Array(buffer);
    };
    generateRandomPrivateKey = (bytesLength = 32) => {
        return window.crypto.getRandomValues(new Uint8Array(bytesLength));
    };
}
else if (typeof process === 'object' && 'node' in process.versions) {
    const req = require;
    const { createHash, randomBytes } = req('crypto');
    sha512 = async (message) => {
        const hash = createHash('sha512');
        hash.update(message);
        return Uint8Array.from(hash.digest());
    };
    generateRandomPrivateKey = (bytesLength = 32) => {
        return new Uint8Array(randomBytes(bytesLength).buffer);
    };
}
else {
    throw new Error("The environment doesn't have sha512 function");
}
function concatTypedArrays(...arrays) {
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
function arrayToHex(uint8a) {
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += uint8a[i].toString(16).padStart(2, '0');
    }
    return hex;
}
function pad64(num) {
    return num.toString(16).padStart(64, '0');
}
function numberToHex(num) {
    const hex = num.toString(16);
    return hex.length & 1 ? `0${hex}` : hex;
}
function hexToArray(hex) {
    hex = hex.length & 1 ? `0${hex}` : hex;
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        let j = i * 2;
        array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
}
function arrayToNumberLE(uint8a) {
    let value = 0n;
    for (let i = 0; i < uint8a.length; i++) {
        value += BigInt(uint8a[i]) << (8n * BigInt(i));
    }
    return value;
}
function mod(a, b = P) {
    const res = a % b;
    return res >= 0n ? res : b + res;
}
function powMod(x, power, order) {
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
function egcd(a, b) {
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
function modInverse(number, modulo = P) {
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
function batchInverse(nums, n = P) {
    const len = nums.length;
    const scratch = new Array(len);
    let acc = 1n;
    for (let i = 0; i < len; i++) {
        if (nums[i] === 0n)
            continue;
        scratch[i] = acc;
        acc = mod(acc * nums[i], n);
    }
    acc = modInverse(acc, n);
    for (let i = len - 1; i >= 0; i--) {
        if (nums[i] === 0n)
            continue;
        let tmp = mod(acc * nums[i], n);
        nums[i] = mod(acc * scratch[i], n);
        acc = tmp;
    }
    return nums;
}
async function sha512ToNumberLE(...args) {
    const messageArray = concatTypedArrays(...args);
    const hash = await sha512(messageArray);
    const value = arrayToNumberLE(hash);
    return mod(value, PRIME_ORDER);
}
function keyPrefix(privateBytes) {
    return privateBytes.slice(ENCODING_LENGTH);
}
function encodePrivate(privateBytes) {
    const last = ENCODING_LENGTH - 1;
    const head = privateBytes.slice(0, ENCODING_LENGTH);
    head[0] &= 248;
    head[last] &= 127;
    head[last] |= 64;
    return arrayToNumberLE(head);
}
function ensureArray(hash) {
    return hash instanceof Uint8Array ? hash : hexToArray(hash);
}
function ensurePrivInputArray(privateKey) {
    if (privateKey instanceof Uint8Array)
        return privateKey;
    if (typeof privateKey === 'string')
        return hexToArray(privateKey.padStart(64, '0'));
    return hexToArray(pad64(BigInt(privateKey)));
}
async function getPublicKey(privateKey) {
    const privBytes = await sha512(ensurePrivInputArray(privateKey));
    const publicKey = BASE_POINT.multiply(encodePrivate(privBytes));
    return typeof privateKey === 'string' ? publicKey.toHex() : publicKey.toRawBytes();
}
exports.getPublicKey = getPublicKey;
async function sign(hash, privateKey) {
    const privBytes = await sha512(ensurePrivInputArray(privateKey));
    const p = encodePrivate(privBytes);
    const P = BASE_POINT.multiply(p);
    const msg = ensureArray(hash);
    const r = await sha512ToNumberLE(keyPrefix(privBytes), msg);
    const R = BASE_POINT.multiply(r);
    const h = await sha512ToNumberLE(R.toRawBytes(), P.toRawBytes(), msg);
    const S = mod(r + h * p, PRIME_ORDER);
    const sig = new SignResult(R, S);
    return typeof hash === 'string' ? sig.toHex() : sig.toRawBytes();
}
exports.sign = sign;
async function verify(signature, hash, publicKey) {
    hash = ensureArray(hash);
    if (!(publicKey instanceof Point))
        publicKey = Point.fromHex(publicKey);
    if (!(signature instanceof SignResult))
        signature = SignResult.fromHex(signature);
    const h = await sha512ToNumberLE(signature.r.toRawBytes(), publicKey.toRawBytes(), hash);
    const Ph = ExtendedPoint.fromAffine(publicKey).multiplyUnsafe(h);
    const Gs = BASE_POINT.multiply(signature.s, false);
    const RPh = ExtendedPoint.fromAffine(signature.r).add(Ph);
    return Gs.equals(RPh);
}
exports.verify = verify;
BASE_POINT._setWindowSize(8);
exports.utils = {
    generateRandomPrivateKey,
    precompute(windowSize = 8, point = BASE_POINT) {
        const cached = point.equals(BASE_POINT) ? point : new Point(point.x, point.y);
        cached._setWindowSize(windowSize);
        cached.multiply(1n);
        return cached;
    }
};

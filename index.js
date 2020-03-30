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
class ProjectivePoint {
    constructor(x, y, z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
    static fromPoint(p) {
        return new ProjectivePoint(p.x, p.y, 1n);
    }
    static batchAffine(points) {
        const toInv = batchInverse(points.map(p => p.z));
        return points.map((p, i) => p.toAffine(toInv[i]));
    }
    equals(other) {
        const a = this;
        const b = other;
        return mod(a.x * b.z) === mod(a.z * b.x) && mod(a.y * b.z) === mod(b.y * a.z);
    }
    add(other) {
        const [X1, Y1, Z1, X2, Y2, Z2] = [this.x, this.y, this.z, other.x, other.y, other.z];
        const { a, d } = exports.CURVE_PARAMS;
        const A = mod(Z1 * Z2);
        const B = mod(A ** 2n);
        const C = mod(X1 * X2);
        const D = mod(Y1 * Y2);
        const E = mod(d * C * D);
        const F = mod(B - E);
        const G = mod(B + E);
        const X3 = mod(A * F * ((X1 + Y1) * (X2 + Y2) - C - D));
        const Y3 = mod(A * G * (D - a * C));
        const Z3 = mod(F * G);
        return new ProjectivePoint(X3, Y3, Z3);
    }
    double() {
        const [X1, Y1, Z1] = [this.x, this.y, this.z];
        const { a, } = exports.CURVE_PARAMS;
        const B = mod((X1 + Y1) ** 2n, P);
        const C = mod(X1 ** 2n, P);
        const D = mod(Y1 ** 2n, P);
        const E = mod(a * C, P);
        const F = mod(E + D, P);
        const H = mod(Z1 ** 2n, P);
        const J = mod(F - 2n * H, P);
        const X3 = mod((B - C - D) * J, P);
        const Y3 = mod(F * (E - D), P);
        const Z3 = mod(F * J, P);
        return new ProjectivePoint(X3, Y3, Z3);
    }
    toAffine(invZ = modInverse(this.z)) {
        const x = mod(this.x * invZ);
        const y = mod(this.y * invZ);
        return new Point(x, y);
    }
}
ProjectivePoint.ZERO_POINT = new ProjectivePoint(0n, 1n, 1n);
class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }
    _setWindowSize(windowSize) {
        this.WINDOW_SIZE = windowSize;
        this.PRECOMPUTES = undefined;
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
        if (mod(x * x - sqrX, P) !== 0n) {
            x = mod(x * I, P);
        }
        const isXOdd = (x & 1n) === 1n;
        if (isLastByteOdd !== isXOdd) {
            x = mod(-x, P);
        }
        return new Point(x, y);
    }
    encode() {
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
    toHex() {
        const bytes = this.encode();
        let hex = '';
        for (let i = 0; i < bytes.length; i++) {
            const value = bytes[i].toString(16);
            hex = `${hex}${value.length > 1 ? value : `0${value}`}`;
        }
        return hex;
    }
    toX25519() {
        const res = (1n + this.y) * modInverse(1n - this.y);
        return mod(res, P);
    }
    equals(other) {
        return this.x === other.x && this.y === other.y;
    }
    negate() {
        return new Point(this.x, mod(-this.y, P));
    }
    add(other) {
        if (!(other instanceof Point)) {
            throw new TypeError('Point#add: expected Point');
        }
        const { d } = exports.CURVE_PARAMS;
        const a = this;
        const b = other;
        const x = (a.x * b.y + b.x * a.y) * modInverse(1n + d * a.x * b.x * a.y * b.y);
        const y = (a.y * b.y + a.x * b.x) * modInverse(1n - d * a.x * b.x * a.y * b.y);
        return new Point(mod(x, P), mod(y, P));
    }
    subtract(other) {
        return this.add(other.negate());
    }
    precomputeWindow(W) {
        if (this.PRECOMPUTES)
            return this.PRECOMPUTES;
        const points = new Array((2 ** W) * W);
        let currPoint = ProjectivePoint.fromPoint(this);
        const winSize = 2 ** W;
        for (let currWin = 0; currWin < 256 / W; currWin++) {
            let offset = currWin * winSize;
            let point = ProjectivePoint.ZERO_POINT;
            for (let i = 0; i < winSize; i++) {
                points[offset + i] = point;
                point = point.add(currPoint);
            }
            currPoint = point;
        }
        let res = points;
        if (W !== 1) {
            res = ProjectivePoint.batchAffine(points).map(p => ProjectivePoint.fromPoint(p));
            this.PRECOMPUTES = res;
        }
        return res;
    }
    multiplyUnsafe(scalar, isAffine = true) {
        if (typeof scalar !== 'number' && typeof scalar !== 'bigint') {
            throw new TypeError('Point#multiply: expected number or bigint');
        }
        let n = mod(BigInt(scalar), PRIME_ORDER);
        if (n <= 0) {
            throw new Error('Point#multiply: invalid scalar, expected positive integer');
        }
        let p = ProjectivePoint.ZERO_POINT;
        let d = ProjectivePoint.fromPoint(this);
        while (n > 0n) {
            if (n & 1n)
                p = p.add(d);
            d = d.double();
            n >>= 1n;
        }
        return isAffine ? p.toAffine() : p;
    }
    multiply(scalar, isAffine = true) {
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
        const winSize = 2 ** W;
        let p = ProjectivePoint.ZERO_POINT;
        for (let byteIdx = 0; byteIdx < 256 / W; byteIdx++) {
            const offset = winSize * byteIdx;
            const masked = Number(n & BigInt(winSize - 1));
            p = p.add(precomputes[offset + masked]);
            n >>= BigInt(W);
        }
        return isAffine ? p.toAffine() : p;
    }
}
exports.Point = Point;
Point.BASE_POINT = new Point(exports.CURVE_PARAMS.Gx, exports.CURVE_PARAMS.Gy);
Point.ZERO_POINT = new Point(0n, 1n);
class SignResult {
    constructor(r, s) {
        this.r = r;
        this.s = s;
    }
    static fromHex(hex) {
        hex = normalizeHash(hex);
        const r = Point.fromHex(hex.slice(0, 32));
        const s = arrayToNumberLE(hex.slice(32));
        return new SignResult(r, s);
    }
    toHex() {
        const numberBytes = numberToArray(this.s).reverse();
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
exports.SignResult = SignResult;
const { BASE_POINT } = Point;
let sha512;
if (typeof window == 'object' && 'crypto' in window) {
    sha512 = async (message) => {
        const buffer = await window.crypto.subtle.digest('SHA-512', message.buffer);
        return new Uint8Array(buffer);
    };
}
else if (typeof process === 'object' && 'node' in process.versions) {
    const req = require;
    const { createHash } = req('crypto');
    sha512 = async (message) => {
        const hash = createHash('sha512');
        hash.update(message);
        return Uint8Array.from(hash.digest());
    };
}
else {
    throw new Error("The environment doesn't have sha512 function");
}
function concatTypedArrays(...args) {
    const result = new Uint8Array(args.reduce((a, arr) => a + arr.length, 0));
    for (let i = 0, pad = 0; i < args.length; i++) {
        const arr = args[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
function numberToArray(num, padding) {
    let hex = num.toString(16);
    if (padding)
        hex = hex.padStart(padding);
    hex = hex.length & 1 ? `0${hex}` : hex;
    const len = hex.length / 2;
    const u8 = new Uint8Array(len);
    for (let j = 0, i = 0; i < hex.length; i += 2, j++) {
        u8[j] = parseInt(hex[i] + hex[i + 1], 16);
    }
    return u8;
}
function arrayToNumberLE(bytes) {
    let value = 0n;
    for (let i = 0; i < bytes.length; i++) {
        value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(i));
    }
    return value;
}
function arrayToNumber(bytes) {
    let value = 0n;
    for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
        value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
    }
    return value;
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
function hexToArray(hash) {
    hash = hash.length & 1 ? `0${hash}` : hash;
    const len = hash.length;
    const result = new Uint8Array(len / 2);
    for (let i = 0, j = 0; i < len - 1; i += 2, j++) {
        result[j] = parseInt(hash[i] + hash[i + 1], 16);
    }
    return result;
}
function hexToNumber(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
    }
    return BigInt(`0x${hex}`);
}
async function hashNumber(...args) {
    const messageArray = concatTypedArrays(...args);
    const hash = await sha512(messageArray);
    const value = arrayToNumberLE(hash);
    return mod(value, PRIME_ORDER);
}
function getPrivateBytes(privateKey) {
    return sha512(privateKey instanceof Uint8Array ? privateKey : numberToArray(privateKey, 64));
}
function keyPrefix(privateBytes) {
    return privateBytes.slice(ENCODING_LENGTH);
}
function mod(a, b = P) {
    const res = a % b;
    return res >= 0n ? res : b + res;
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
function encodePrivate(privateBytes) {
    const last = ENCODING_LENGTH - 1;
    const head = privateBytes.slice(0, ENCODING_LENGTH);
    head[0] &= 248;
    head[last] &= 127;
    head[last] |= 64;
    return arrayToNumberLE(head);
}
function normalizePrivateKey(privateKey) {
    let res;
    if (privateKey instanceof Uint8Array) {
        res = arrayToNumber(privateKey);
    }
    else if (typeof privateKey === 'string') {
        res = hexToNumber(privateKey);
    }
    else {
        res = BigInt(privateKey);
    }
    return res;
}
function normalizePublicKey(publicKey) {
    return publicKey instanceof Point ? publicKey : Point.fromHex(publicKey);
}
function normalizePoint(point, privateKey) {
    if (privateKey instanceof Uint8Array) {
        return point.encode();
    }
    if (typeof privateKey === 'string') {
        return point.toHex();
    }
    return point;
}
function normalizeSignature(signature) {
    return signature instanceof SignResult ? signature : SignResult.fromHex(signature);
}
function normalizeHash(hash) {
    return hash instanceof Uint8Array ? hash : hexToArray(hash);
}
async function getPublicKey(privateKey) {
    const multiplier = normalizePrivateKey(privateKey);
    const privateBytes = await getPrivateBytes(multiplier);
    const privateInt = encodePrivate(privateBytes);
    const publicKey = BASE_POINT.multiply(privateInt);
    const p = normalizePoint(publicKey, privateKey);
    return p;
}
exports.getPublicKey = getPublicKey;
async function sign(hash, privateKey) {
    const message = normalizeHash(hash);
    privateKey = normalizePrivateKey(privateKey);
    const publicKey = await getPublicKey(privateKey);
    const privateBytes = await getPrivateBytes(privateKey);
    const privatePrefix = keyPrefix(privateBytes);
    const r = await hashNumber(privatePrefix, message);
    const R = BASE_POINT.multiply(r);
    const h = await hashNumber(R.encode(), publicKey.encode(), message);
    const S = mod(r + h * encodePrivate(privateBytes), PRIME_ORDER);
    const signature = new SignResult(R, S).toHex();
    return hash instanceof Uint8Array ? hexToArray(signature) : signature;
}
exports.sign = sign;
async function verify(signature, hash, publicKey) {
    hash = normalizeHash(hash);
    publicKey = normalizePublicKey(publicKey);
    signature = normalizeSignature(signature);
    const h = await hashNumber(signature.r.encode(), publicKey.encode(), hash);
    const S = BASE_POINT.multiply(signature.s, false);
    const R = ProjectivePoint.fromPoint(signature.r).add(publicKey.multiplyUnsafe(h, false));
    return S.equals(R);
}
exports.verify = verify;
BASE_POINT._setWindowSize(4);
exports.utils = {
    precompute(windowSize = 4, point = BASE_POINT) {
        const cached = point.equals(BASE_POINT) ? point : new Point(point.x, point.y);
        cached._setWindowSize(windowSize);
        cached.multiply(1n);
        return cached;
    }
};

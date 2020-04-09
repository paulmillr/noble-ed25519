"use strict";
/*! noble-ristretto255 - MIT License (c) Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
const mask64Bits = (1n << 64n) - 1n;
const low51bitMask = (1n << 51n) - 1n;
const CURVE = {
    a: -1n,
    d: 37095705934669439343138083508754565189542113879843219016388785533085940283555n,
    P: 2n ** 255n - 19n,
    n: 2n ** 252n + 27742317777372353535851937790883648493n,
    h: 8n,
    Gx: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
    Gy: 46316835694926478169428394003475163141307993866256225615783033603165251855960n,
};
const D2 = 16295367250680780974490674513165176452449235426866156013048779062215315747161n;
const SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
const INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578n;
const SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235n;
function isNegative(t) {
    const bytes = toBytesLE(mod(t));
    return Boolean(bytes[0] & 1);
}
function mod(a, b = CURVE.P) {
    const res = a % b;
    return res >= 0 ? res : b + res;
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
function modInverse(number, modulo = exports.P) {
    if (number === 0n || modulo <= 0n) {
        throw new Error('modInverse: expected positive integers');
    }
    let [gcd, x] = egcd(mod(number, modulo), modulo);
    if (gcd !== 1n) {
        throw new Error('modInverse: does not exist');
    }
    return mod(x, modulo);
}
exports.modInverse = modInverse;
function invertSqrt(t) {
    return sqrtRatio(1n, t);
}
function pow2k(t, power) {
    let res = t;
    while (power-- > 0n) {
        res = res * res;
        res %= exports.P;
    }
    return res;
}
function pow_2_252_3(t) {
    const t0 = t * t;
    const t1 = t0 ** 4n;
    const t2 = t * t1;
    const t3 = t0 * t2;
    const t4 = t3 ** 2n;
    const t5 = t2 * t4;
    const t6 = pow2k(t5, 5n);
    const t7 = (t6 * t5) % exports.P;
    const t8 = pow2k(t7, 10n);
    const t9 = (t8 * t7) % exports.P;
    const t10 = pow2k(t9, 20n);
    const t11 = (t10 * t9) % exports.P;
    const t12 = pow2k(t11, 10n);
    const t13 = (t12 * t7) % exports.P;
    const t14 = pow2k(t13, 50n);
    const t15 = (t14 * t13) % exports.P;
    const t16 = pow2k(t15, 100n);
    const t17 = (t16 * t15) % exports.P;
    const t18 = pow2k(t17, 50n);
    const t19 = (t18 * t13) % exports.P;
    const t20 = (t19 * t19) % exports.P;
    const t21 = (t20 * t20 * t) % exports.P;
    return t21;
}
function pow_2_252_3_fast(t) {
    const t0 = mod(t * t);
    const t1 = mod(t0 ** 4n);
    const t2 = mod(t * t1);
    const t3 = mod(t0 * t2);
    const t5 = mod(t2 * t3 * t3);
    let t7 = t5;
    for (let i = 0; i < 5; i++) {
        t7 *= t7;
        t7 %= exports.P;
    }
    t7 *= t5;
    t7 %= exports.P;
    let t9 = t7;
    for (let i = 0; i < 10; i++) {
        t9 *= t9;
        t9 %= exports.P;
    }
    t9 *= t7;
    t9 %= exports.P;
    let t13 = t9;
    for (let i = 0; i < 20; i++) {
        t13 *= t13;
        t13 %= exports.P;
    }
    t13 *= t9;
    t13 %= exports.P;
    for (let i = 0; i < 10; i++) {
        t13 *= t13;
        t13 %= exports.P;
    }
    t13 *= t7;
    t13 %= exports.P;
    let t15 = t13;
    for (let i = 0; i < 50; i++) {
        t15 *= t15;
        t15 %= exports.P;
    }
    t15 *= t13;
    t15 %= exports.P;
    let t19 = t15;
    for (let i = 0; i < 100; i++) {
        t19 *= t19;
        t19 %= exports.P;
    }
    t19 *= t15;
    t19 %= exports.P;
    for (let i = 0; i < 50; i++) {
        t19 *= t19;
        t19 %= exports.P;
    }
    t19 *= t13;
    t19 %= exports.P;
    let t20 = (t19 * t19) % exports.P;
    let t21 = (t20 * t20 * t) % exports.P;
    return t21;
}
function sqrtRatio(t, v) {
    const v3 = mod(v * v * v);
    const v7 = mod(v3 * v3 * v);
    let r = mod(pow_2_252_3_fast(t * v7) * t * v3);
    const check = mod(r * r * v);
    const i = SQRT_M1;
    const correctSignSqrt = check === t;
    const flippedSignSqrt = check === mod(-t);
    const flippedSignSqrtI = check === mod(mod(-t) * i);
    const rPrime = mod(SQRT_M1 * r);
    r = flippedSignSqrt || flippedSignSqrtI ? rPrime : r;
    if (isNegative(r))
        r = mod(-r);
    const isNotZeroSquare = correctSignSqrt || flippedSignSqrt;
    return { isNotZeroSquare, value: mod(r) };
}
exports.sqrtRatio = sqrtRatio;
function toBytesBE(t, length = 0) {
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
function toBytesLE(t, length = 0) {
    return toBytesBE(t, length).reverse();
}
function condSwap(t, other, choice) {
    choice = BigInt(choice);
    const mask = choice !== 0n ? mask64Bits : choice;
    const tmp = mask & (t ^ other);
    return [mod(t ^ tmp), mod(other ^ tmp)];
}
function load8(input, padding = 0) {
    return (BigInt(input[0 + padding]) |
        (BigInt(input[1 + padding]) << 8n) |
        (BigInt(input[2 + padding]) << 16n) |
        (BigInt(input[3 + padding]) << 24n) |
        (BigInt(input[4 + padding]) << 32n) |
        (BigInt(input[5 + padding]) << 40n) |
        (BigInt(input[6 + padding]) << 48n) |
        (BigInt(input[7 + padding]) << 56n));
}
function BigInt_fromBytes(bytes) {
    const octet1 = load8(bytes, 0) & low51bitMask;
    const octet2 = (load8(bytes, 6) >> 3n) & low51bitMask;
    const octet3 = (load8(bytes, 12) >> 6n) & low51bitMask;
    const octet4 = (load8(bytes, 19) >> 1n) & low51bitMask;
    const octet5 = (load8(bytes, 24) >> 12n) & low51bitMask;
    return mod(octet1 + (octet2 << 51n) + (octet3 << 102n) + (octet4 << 153n) + (octet5 << 204n));
}
exports.P = CURVE.P;
exports.PRIME_ORDER = CURVE.n;
class ProjectiveP1xP1 {
    constructor(x, y, z, T) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.T = T;
        this.x = mod(this.x);
        this.y = mod(this.y);
        this.z = mod(this.z);
        this.T = mod(this.T);
    }
}
exports.ProjectiveP1xP1 = ProjectiveP1xP1;
ProjectiveP1xP1.ZERO = new ProjectiveP1xP1(0n, 1n, 1n, 1n);
class ProjectiveP2 {
    constructor(x, y, z) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.x = mod(this.x);
        this.y = mod(this.y);
        this.z = mod(this.z);
    }
    static fromP1xP1(point) {
        return new ProjectiveP2(mod(point.x * point.T), mod(point.y * point.T), mod(point.z * point.T));
    }
    static fromP3(point) {
        return new ProjectiveP2(point.x, point.y, point.z);
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
exports.ProjectiveP2 = ProjectiveP2;
ProjectiveP2.ZERO = new ProjectiveP2(0n, 1n, 1n);
class ProjectiveP3 {
    constructor(x, y, z, T) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.T = T;
        this.x = mod(this.x);
        this.y = mod(this.y);
        this.z = mod(this.z);
        this.T = mod(this.T);
    }
    static fromP1xP1(point) {
        return new ProjectiveP3(mod(point.x * point.T), mod(point.y * point.z), mod(point.z * point.T), mod(point.x * point.y));
    }
    static fromP2(point) {
        return new ProjectiveP3(mod(point.x * point.z), mod(point.y * point.z), mod(point.z ** 2n), mod(point.x * point.y));
    }
    toProjectiveNielsPoint() {
        return new ProjectiveP3(mod(this.y + this.x), mod(this.y - this.x), this.z, mod(this.T * D2));
    }
    toExtendedProjective() {
        return new ProjectiveP3(mod(this.x * this.z), mod(this.y * this.z), mod(this.z * this.z), mod(this.x * this.y));
    }
    toExtendedCompleted() {
        return new ProjectiveP3(mod(this.x * this.T), mod(this.y * this.z), mod(this.z * this.T), mod(this.x * this.y));
    }
    addCached(other) {
        const yPlusX = this.y + this.x;
        const yMinusX = this.y - this.x;
        const PP = yPlusX * other.yPlusX;
        const MM = yMinusX * other.yMinusX;
        const TT2 = this.T * other.T2d;
        const ZZ = this.z * other.z;
        const ZZ2 = ZZ + ZZ;
        return new ProjectiveP1xP1(mod(PP - MM), mod(PP + MM), mod(ZZ2 + TT2), mod(ZZ2 - TT2));
    }
    subtractCached(other) {
        const yPlusX = this.y + this.x;
        const yMinusX = this.y - this.x;
        const PP = yPlusX * other.yMinusX;
        const MM = yMinusX * other.yPlusX;
        const TT2 = this.T * other.T2d;
        const ZZ = this.z * other.z;
        const ZZ2 = ZZ + ZZ;
        return new ProjectiveP1xP1(mod(PP - MM), mod(PP + MM), mod(ZZ2 - TT2), mod(ZZ2 + TT2));
    }
    addAffine(other) {
        const yPlusX = this.y + this.x;
        const yMinusX = this.y - this.x;
        const PP = yPlusX * other.yPlusX;
        const MM = yMinusX * other.yMinusX;
        const TT2 = this.T * other.T2d;
        const ZZ = this.z * this.z;
        const ZZ2 = ZZ + ZZ;
        return new ProjectiveP1xP1(mod(PP - MM), mod(PP + MM), mod(ZZ2 + TT2), mod(ZZ2 - TT2));
    }
    subtractAffine(other) {
        const yPlusX = this.y + this.x;
        const yMinusX = this.y - this.x;
        const PP = yPlusX * other.yMinusX;
        const MM = yMinusX * other.yPlusX;
        const TT2 = this.T * other.T2d;
        const ZZ = this.z * this.z;
        const ZZ2 = ZZ + ZZ;
        return new ProjectiveP1xP1(mod(PP - MM), mod(PP + MM), mod(ZZ2 - TT2), mod(ZZ2 + TT2));
    }
    add(other) {
        const cached = ProjectiveCached.fromP3(other);
        const result = this.addCached(cached);
        return ProjectiveP3.fromP1xP1(result);
    }
    subtract(other) {
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
    multiply(n) {
        let q = ProjectiveP3.ZERO;
        for (let db = this; n > 0n; n >>= 1n, db = db.double()) {
            if ((n & 1n) === 1n) {
                q = q.add(db);
            }
        }
        return q;
    }
    equals(other) {
        const t1 = mod(this.x * other.z);
        const t2 = mod(other.x * this.z);
        const t3 = mod(this.y * other.z);
        const t4 = mod(other.y * this.z);
        return t1 === t2 && t3 === t4;
    }
}
exports.ProjectiveP3 = ProjectiveP3;
ProjectiveP3.ZERO = new ProjectiveP3(0n, 1n, 1n, 0n);
class ProjectiveCached {
    constructor(yPlusX, yMinusX, z, T2d) {
        this.yPlusX = yPlusX;
        this.yMinusX = yMinusX;
        this.z = z;
        this.T2d = T2d;
    }
    static ZERO() {
        return new ProjectiveCached(1n, 1n, 1n, 0n);
    }
    static fromP3(point) {
        return new ProjectiveCached(mod(point.y + point.x), mod(point.y - point.x), point.z, mod(point.T * D2));
    }
}
exports.ProjectiveCached = ProjectiveCached;
class AffineCached {
    constructor(yPlusX, yMinusX, T2d) {
        this.yPlusX = yPlusX;
        this.yMinusX = yMinusX;
        this.T2d = T2d;
        this.yPlusX = mod(this.yPlusX);
        this.yMinusX = mod(this.yMinusX);
        this.T2d = mod(this.T2d);
    }
    static fromP3(point) {
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
}
exports.AffineCached = AffineCached;
if (typeof window == 'object' && 'crypto' in window) {
    exports.sha512 = async (message) => {
        const buffer = await window.crypto.subtle.digest('SHA-512', message.buffer);
        return new Uint8Array(buffer);
    };
}
else if (typeof process === 'object' && 'node' in process.versions) {
    const { createHash } = require('crypto');
    exports.sha512 = async (message) => {
        const hash = createHash('sha512');
        hash.update(message);
        return Uint8Array.from(hash.digest());
    };
}
else {
    throw new Error("The environment doesn't have sha512 function");
}
function fromHexBE(hex) {
    return BigInt(`0x${hex}`);
}
function fromBytesBE(bytes) {
    if (typeof bytes === 'string') {
        return fromHexBE(bytes);
    }
    let value = 0n;
    for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
        value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
    }
    return value;
}
function fromBytesLE(bytes) {
    let value = 0n;
    for (let i = 0; i < bytes.length; i++) {
        value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(i));
    }
    return value;
}
exports.fromBytesLE = fromBytesLE;
function hexToBytes(hash) {
    hash = hash.length & 1 ? `0${hash}` : hash;
    const len = hash.length;
    const result = new Uint8Array(len / 2);
    for (let i = 0, j = 0; i < len - 1; i += 2, j++) {
        result[j] = parseInt(hash[i] + hash[i + 1], 16);
    }
    return result;
}
exports.hexToBytes = hexToBytes;
function toBigInt(num) {
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
exports.toBigInt = toBigInt;
function isBytesEquals(b1, b2) {
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
exports.isBytesEquals = isBytesEquals;
function numberToBytes(num) {
    let hex = num.toString(16);
    hex = hex.length & 1 ? `0${hex}` : hex;
    const len = hex.length / 2;
    const u8 = new Uint8Array(len);
    for (let j = 0, i = 0; i < hex.length; i += 2, j++) {
        u8[j] = parseInt(hex[i] + hex[i + 1], 16);
    }
    return u8;
}
exports.numberToBytes = numberToBytes;
function concatTypedArrays(...arrays) {
    const result = new Uint8Array(arrays.reduce((a, arr) => a + arr.length, 0));
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
exports.concatTypedArrays = concatTypedArrays;
const ENCODING_LENGTH = 32;
class RistrettoPoint {
    constructor(point) {
        this.point = point;
    }
    static fromHash(hash) {
        const r1 = BigInt_fromBytes(hash.slice(0, ENCODING_LENGTH));
        const R1 = this.elligatorRistrettoFlavor(r1);
        const r2 = BigInt_fromBytes(hash.slice(ENCODING_LENGTH, ENCODING_LENGTH * 2));
        const R2 = this.elligatorRistrettoFlavor(r2);
        return new RistrettoPoint(R1.add(R2));
    }
    static elligatorRistrettoFlavor(r0) {
        const oneMinusDSq = mod(1n - CURVE.d ** 2n);
        const dMinusOneSq = (CURVE.d - 1n) ** 2n;
        const r = SQRT_M1 * (r0 * r0);
        const NS = mod((r + 1n) * oneMinusDSq);
        let c = mod(-1n);
        const D = mod((c - CURVE.d * r) * mod(r + CURVE.d));
        let { isNotZeroSquare, value: S } = sqrtRatio(NS, D);
        let sPrime = mod(S * r0);
        sPrime = isNegative(sPrime) ? sPrime : mod(-sPrime);
        S = isNotZeroSquare ? S : sPrime;
        c = isNotZeroSquare ? c : r;
        const NT = c * (r - 1n) * dMinusOneSq - D;
        const sSquared = S * S;
        const projective = new ProjectiveP3(mod((S + S) * D), mod(1n - sSquared), mod(NT * SQRT_AD_MINUS_ONE), mod(1n + sSquared));
        return projective.toExtendedCompleted();
    }
    static fromBytes(bytes) {
        const s = BigInt_fromBytes(bytes);
        const sEncodingIsCanonical = isBytesEquals(toBytesLE(s, ENCODING_LENGTH), bytes);
        const sIsNegative = isNegative(s);
        if (!sEncodingIsCanonical || sIsNegative) {
            throw new Error('Cannot convert bytes to Ristretto Point');
        }
        const s2 = mod(s * s);
        const u1 = mod(1n - s2);
        const u2 = mod(1n + s2);
        const squaredU2 = mod(u2 * u2);
        const v = mod(mod(u1 * u1 * -CURVE.d) - squaredU2);
        const { isNotZeroSquare, value: I } = invertSqrt(mod(v * squaredU2));
        const Dx = I * u2;
        const Dy = I * Dx * v;
        let x = mod((s + s) * Dx);
        if (isNegative(x))
            x = mod(-x);
        const y = mod(u1 * Dy);
        const t = mod(x * y);
        if (!isNotZeroSquare || isNegative(t) || y === 0n) {
            throw new Error('Cannot convert bytes to Ristretto Point');
        }
        return new RistrettoPoint(new ProjectiveP3(x, y, 1n, t));
    }
    toBytes() {
        let { x, y, z, T } = this.point;
        const u1 = mod((z + y) * (z - y));
        const u2 = mod(x * y);
        const { value: invsqrt } = invertSqrt(mod(u2 ** 2n * u1));
        const i1 = mod(invsqrt * u1);
        const i2 = mod(invsqrt * u2);
        const invertedZ = mod(i1 * i2 * T);
        let invertedDenominator = i2;
        const iX = mod(x * SQRT_M1);
        const iY = mod(y * SQRT_M1);
        const enchantedDenominator = mod(i1 * INVSQRT_A_MINUS_D);
        const isRotated = BigInt(isNegative(T * invertedZ));
        x = isRotated ? iY : x;
        y = isRotated ? iX : y;
        invertedDenominator = isRotated ? enchantedDenominator : i2;
        if (isNegative(x * invertedZ))
            y = mod(-y);
        let s = mod((z - y) * invertedDenominator);
        if (isNegative(s))
            s = mod(-s);
        return toBytesLE(s, ENCODING_LENGTH);
    }
    add(other) {
        return new RistrettoPoint(this.point.add(other.point));
    }
    subtract(other) {
        return new RistrettoPoint(this.point.subtract(other.point));
    }
    multiply(n) {
        return new RistrettoPoint(this.point.multiply(n));
    }
    equals(other) {
        return this.point.equals(other.point);
    }
}
exports.RistrettoPoint = RistrettoPoint;
RistrettoPoint.ZERO = new RistrettoPoint(ProjectiveP3.ZERO);
exports.BASE_POINT = new RistrettoPoint(new ProjectiveP3(15112221349535400772501151409588531511454012693041857206046113283949847762202n, 46316835694926478169428394003475163141307993866256225615783033603165251855960n, 1n, 46827403850823179245072216630277197565144205554125654976674165829533817101731n));

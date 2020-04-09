"use strict";
/*! noble-ed25519 - MIT License (c) Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
const CURVE = {
    a: -1n,
    d: 37095705934669439343138083508754565189542113879843219016388785533085940283555n,
    P: 2n ** 255n - 19n,
    n: 2n ** 252n + 27742317777372353535851937790883648493n,
    h: 8n,
    Gx: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
    Gy: 46316835694926478169428394003475163141307993866256225615783033603165251855960n,
};
exports.CURVE = CURVE;
const D2 = 16295367250680780974490674513165176452449235426866156013048779062215315747161n;
const SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
const INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578n;
const SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235n;
const TORSION_SUBGROUP = [
    '0100000000000000000000000000000000000000000000000000000000000000',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    '0000000000000000000000000000000000000000000000000000000000000080',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
    '0000000000000000000000000000000000000000000000000000000000000000',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
];
const ENCODING_LENGTH = 32;
const P = CURVE.P;
const PRIME_ORDER = CURVE.n;
const I = powMod(2n, (P - 1n) / 4n, P);
class ExtendedPoint {
    constructor(x, y, z, t) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.t = t;
    }
    static fromAffine(p) {
        if (p.equals(Point.ZERO))
            return ExtendedPoint.ZERO;
        return new ExtendedPoint(p.x, p.y, 1n, mod(p.x * p.y));
    }
    static batchAffine(points) {
        const toInv = batchInverse(points.map((p) => p.z));
        return points.map((p, i) => p.toAffine(toInv[i]));
    }
    static fromUncompleteExtended(x, y, z, t) {
        return new ExtendedPoint(mod(x * t), mod(y * z), mod(z * t), mod(x * y));
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
    subtract(other) {
        return this.add(other.negate());
    }
    multiplyUnsafe(scalar) {
        if (typeof scalar !== 'number' && typeof scalar !== 'bigint') {
            throw new TypeError('Point#multiply: expected number or bigint');
        }
        let n = mod(BigInt(scalar), PRIME_ORDER);
        if (n <= 0) {
            throw new Error('Point#multiply: invalid scalar, expected positive integer');
        }
        let p = ExtendedPoint.ZERO;
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
exports.ExtendedPoint = ExtendedPoint;
ExtendedPoint.BASE = new ExtendedPoint(CURVE.Gx, CURVE.Gy, 1n, mod(CURVE.Gx * CURVE.Gy));
ExtendedPoint.ZERO = new ExtendedPoint(0n, 1n, 1n, 0n);
class RistrettoPoint {
    constructor(point) {
        this.point = point;
    }
    static fromHash(hash) {
        const r1 = arrayToNumberRst(hash.slice(0, ENCODING_LENGTH));
        const R1 = this.elligatorRistrettoFlavor(r1);
        const r2 = arrayToNumberRst(hash.slice(ENCODING_LENGTH, ENCODING_LENGTH * 2));
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
        sPrime = edIsNegative(sPrime) ? sPrime : mod(-sPrime);
        S = isNotZeroSquare ? S : sPrime;
        c = isNotZeroSquare ? c : r;
        const NT = c * (r - 1n) * dMinusOneSq - D;
        const sSquared = S * S;
        return ExtendedPoint.fromUncompleteExtended((S + S) * D, 1n - sSquared, NT * SQRT_AD_MINUS_ONE, 1n + sSquared);
    }
    static fromBytes(bytes) {
        const s = arrayToNumberRst(bytes);
        const sEncodingIsCanonical = arraysAreEqual(numberToArrayPadded(s, ENCODING_LENGTH), bytes);
        const sIsNegative = edIsNegative(s);
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
        if (edIsNegative(x))
            x = mod(-x);
        const y = mod(u1 * Dy);
        const t = mod(x * y);
        if (!isNotZeroSquare || edIsNegative(t) || y === 0n) {
            throw new Error('Cannot convert bytes to Ristretto Point');
        }
        return new RistrettoPoint(new ExtendedPoint(x, y, 1n, t));
    }
    toBytes() {
        let { x, y, z, t } = this.point;
        const u1 = mod((z + y) * (z - y));
        const u2 = mod(x * y);
        const { value: invsqrt } = invertSqrt(mod(u2 ** 2n * u1));
        const i1 = mod(invsqrt * u1);
        const i2 = mod(invsqrt * u2);
        const invertedZ = mod(i1 * i2 * t);
        let invertedDenominator = i2;
        const iX = mod(x * SQRT_M1);
        const iY = mod(y * SQRT_M1);
        const enchantedDenominator = mod(i1 * INVSQRT_A_MINUS_D);
        const isRotated = BigInt(edIsNegative(t * invertedZ));
        x = isRotated ? iY : x;
        y = isRotated ? iX : y;
        invertedDenominator = isRotated ? enchantedDenominator : i2;
        if (edIsNegative(x * invertedZ))
            y = mod(-y);
        let s = mod((z - y) * invertedDenominator);
        if (edIsNegative(s))
            s = mod(-s);
        return numberToArrayPadded(s, ENCODING_LENGTH);
    }
    equals(other) {
        return this.point.equals(other.point);
    }
    add(other) {
        return new RistrettoPoint(this.point.add(other.point));
    }
    subtract(other) {
        return new RistrettoPoint(this.point.subtract(other.point));
    }
    multiplyUnsafe(n) {
        return new RistrettoPoint(this.point.multiplyUnsafe(n));
    }
}
exports.RistrettoPoint = RistrettoPoint;
RistrettoPoint.BASE = new RistrettoPoint(ExtendedPoint.BASE);
RistrettoPoint.ZERO = new RistrettoPoint(ExtendedPoint.ZERO);
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
        const { d } = CURVE;
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
    wNAF(n) {
        const W = this.WINDOW_SIZE || 1;
        if (256 % W) {
            throw new Error('Point#multiply: Invalid precomputation window, must be power of 2');
        }
        const precomputes = this.precomputeWindow(W);
        let p = ExtendedPoint.ZERO;
        let f = ExtendedPoint.ZERO;
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
        const n = mod(BigInt(scalar), PRIME_ORDER);
        if (n <= 0) {
            throw new Error('Point#multiply: invalid scalar, expected positive integer');
        }
        const [point, fake] = this.wNAF(n);
        return isAffine ? ExtendedPoint.batchAffine([point, fake])[0] : point;
    }
}
exports.Point = Point;
Point.BASE = new Point(CURVE.Gx, CURVE.Gy);
Point.ZERO = new Point(0n, 1n);
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
        const res = new Uint8Array(ENCODING_LENGTH * 2);
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
let generateRandomPrivateKey = (bytesLength = 32) => new Uint8Array(bytesLength);
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
    return num.toString(16).padStart(ENCODING_LENGTH * 2, '0');
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
function numberToHex(num) {
    const hex = num.toString(16);
    return hex.length & 1 ? `0${hex}` : hex;
}
function numberToArrayPadded(num, length = 0) {
    const hex = numberToHex(num).padStart(length * 2, '0');
    return hexToArray(hex).reverse();
}
function edIsNegative(t) {
    const bytes = numberToArrayPadded(mod(t));
    return Boolean(bytes[0] & 1);
}
function arrayToNumberLE(uint8a) {
    let value = 0n;
    for (let i = 0; i < uint8a.length; i++) {
        value += BigInt(uint8a[i]) << (8n * BigInt(i));
    }
    return value;
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
const low51bitMask = (1n << 51n) - 1n;
function arrayToNumberRst(bytes) {
    const octet1 = load8(bytes, 0) & low51bitMask;
    const octet2 = (load8(bytes, 6) >> 3n) & low51bitMask;
    const octet3 = (load8(bytes, 12) >> 6n) & low51bitMask;
    const octet4 = (load8(bytes, 19) >> 1n) & low51bitMask;
    const octet5 = (load8(bytes, 24) >> 12n) & low51bitMask;
    return mod(octet1 + (octet2 << 51n) + (octet3 << 102n) + (octet4 << 153n) + (octet5 << 204n));
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
exports.modInverse = modInverse;
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
function invertSqrt(t) {
    return sqrtRatio(1n, t);
}
function pow2k(t, power) {
    let res = t;
    while (power-- > 0n) {
        res = res * res;
        res %= P;
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
    const t7 = (t6 * t5) % P;
    const t8 = pow2k(t7, 10n);
    const t9 = (t8 * t7) % P;
    const t10 = pow2k(t9, 20n);
    const t11 = (t10 * t9) % P;
    const t12 = pow2k(t11, 10n);
    const t13 = (t12 * t7) % P;
    const t14 = pow2k(t13, 50n);
    const t15 = (t14 * t13) % P;
    const t16 = pow2k(t15, 100n);
    const t17 = (t16 * t15) % P;
    const t18 = pow2k(t17, 50n);
    const t19 = (t18 * t13) % P;
    const t20 = (t19 * t19) % P;
    const t21 = (t20 * t20 * t) % P;
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
    let t20 = (t19 * t19) % P;
    let t21 = (t20 * t20 * t) % P;
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
    if (edIsNegative(r))
        r = mod(-r);
    const isNotZeroSquare = correctSignSqrt || flippedSignSqrt;
    return { isNotZeroSquare, value: mod(r) };
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
function arraysAreEqual(b1, b2) {
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
function ensurePrivInputArray(privateKey) {
    if (privateKey instanceof Uint8Array)
        return privateKey;
    if (typeof privateKey === 'string')
        return hexToArray(privateKey.padStart(ENCODING_LENGTH * 2, '0'));
    return hexToArray(pad64(BigInt(privateKey)));
}
async function getPublicKey(privateKey) {
    const privBytes = await sha512(ensurePrivInputArray(privateKey));
    const publicKey = Point.BASE.multiply(encodePrivate(privBytes));
    return typeof privateKey === 'string' ? publicKey.toHex() : publicKey.toRawBytes();
}
exports.getPublicKey = getPublicKey;
async function sign(hash, privateKey) {
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
exports.sign = sign;
async function verify(signature, hash, publicKey) {
    hash = ensureArray(hash);
    if (!(publicKey instanceof Point))
        publicKey = Point.fromHex(publicKey);
    if (!(signature instanceof SignResult))
        signature = SignResult.fromHex(signature);
    const h = await sha512ToNumberLE(signature.r.toRawBytes(), publicKey.toRawBytes(), hash);
    const Ph = ExtendedPoint.fromAffine(publicKey).multiplyUnsafe(h);
    const Gs = Point.BASE.multiply(signature.s, false);
    const RPh = ExtendedPoint.fromAffine(signature.r).add(Ph);
    return Gs.equals(RPh);
}
exports.verify = verify;
Point.BASE._setWindowSize(8);
exports.utils = {
    generateRandomPrivateKey,
    sha512,
    precompute(windowSize = 8, point = Point.BASE) {
        const cached = point.equals(Point.BASE) ? point : new Point(point.x, point.y);
        cached._setWindowSize(windowSize);
        cached.multiply(1n);
        return cached;
    },
};

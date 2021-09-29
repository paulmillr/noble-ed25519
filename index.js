"use strict";
/*! noble-ed25519 - MIT License (c) Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
exports.utils = exports.verify = exports.sign = exports.getPublicKey = exports.SignResult = exports.Signature = exports.Point = exports.ExtendedPoint = exports.CURVE = void 0;
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
const B32 = 32;
const SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
const SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235n;
const INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578n;
const ONE_MINUS_D_SQ = 1159843021668779879193775521855586647937357759715417654439879720876111806838n;
const D_MINUS_ONE_SQ = 40440834346308536858101042469323190826248399146238708352240133220865137265952n;
class ExtendedPoint {
    constructor(x, y, z, t) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.t = t;
    }
    static fromAffine(p) {
        if (!(p instanceof Point)) {
            throw new TypeError('ExtendedPoint#fromAffine: expected Point');
        }
        if (p.equals(Point.ZERO))
            return ExtendedPoint.ZERO;
        return new ExtendedPoint(p.x, p.y, 1n, mod(p.x * p.y));
    }
    static toAffineBatch(points) {
        const toInv = invertBatch(points.map((p) => p.z));
        return points.map((p, i) => p.toAffine(toInv[i]));
    }
    static normalizeZ(points) {
        return this.toAffineBatch(points).map(this.fromAffine);
    }
    static fromRistrettoHash(hash) {
        const r1 = bytes255ToNumberLE(hash.slice(0, B32));
        const R1 = this.calcElligatorRistrettoMap(r1);
        const r2 = bytes255ToNumberLE(hash.slice(B32, B32 * 2));
        const R2 = this.calcElligatorRistrettoMap(r2);
        return R1.add(R2);
    }
    static calcElligatorRistrettoMap(r0) {
        const { d } = CURVE;
        const r = mod(SQRT_M1 * r0 * r0);
        const Ns = mod((r + 1n) * ONE_MINUS_D_SQ);
        let c = -1n;
        const D = mod((c - d * r) * mod(r + d));
        let { isValid: Ns_D_is_sq, value: s } = uvRatio(Ns, D);
        let s_ = mod(s * r0);
        if (!edIsNegative(s_))
            s_ = mod(-s_);
        if (!Ns_D_is_sq)
            s = s_;
        if (!Ns_D_is_sq)
            c = r;
        const Nt = mod(c * (r - 1n) * D_MINUS_ONE_SQ - D);
        const s2 = s * s;
        const W0 = mod((s + s) * D);
        const W1 = mod(Nt * SQRT_AD_MINUS_ONE);
        const W2 = mod(1n - s2);
        const W3 = mod(1n + s2);
        return new ExtendedPoint(mod(W0 * W3), mod(W2 * W1), mod(W1 * W3), mod(W0 * W2));
    }
    static fromRistrettoBytes(bytes) {
        const { a, d } = CURVE;
        const emsg = 'ExtendedPoint.fromRistrettoBytes: Cannot convert bytes to Ristretto Point';
        const s = bytes255ToNumberLE(bytes);
        if (!equalBytes(numberToBytesPadded(s, B32), bytes) || edIsNegative(s))
            throw new Error(emsg);
        const s2 = mod(s * s);
        const u1 = mod(1n + a * s2);
        const u2 = mod(1n - a * s2);
        const u1_2 = mod(u1 * u1);
        const u2_2 = mod(u2 * u2);
        const v = mod(a * d * u1_2 - u2_2);
        const { isValid, value: I } = invertSqrt(mod(v * u2_2));
        const Dx = mod(I * u2);
        const Dy = mod(I * Dx * v);
        let x = mod((s + s) * Dx);
        if (edIsNegative(x))
            x = mod(-x);
        const y = mod(u1 * Dy);
        const t = mod(x * y);
        if (!isValid || edIsNegative(t) || y === 0n)
            throw new Error(emsg);
        return new ExtendedPoint(x, y, 1n, t);
    }
    toRistrettoBytes() {
        let { x, y, z, t } = this;
        const u1 = mod((z + y) * (z - y));
        const u2 = mod(x * y);
        const { value: invsqrt } = invertSqrt(mod(u1 * u2 ** 2n));
        const D1 = mod(invsqrt * u1);
        const D2 = mod(invsqrt * u2);
        const zInv = mod(D1 * D2 * t);
        let D;
        if (edIsNegative(t * zInv)) {
            [x, y] = [mod(y * SQRT_M1), mod(x * SQRT_M1)];
            D = mod(D1 * INVSQRT_A_MINUS_D);
        }
        else {
            D = D2;
        }
        if (edIsNegative(x * zInv))
            y = mod(-y);
        let s = mod((z - y) * D);
        if (edIsNegative(s))
            s = mod(-s);
        return numberToBytesPadded(s, B32);
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
        if (!isValidScalar(scalar))
            throw new TypeError('Point#multiply: expected number or bigint');
        let n = mod(BigInt(scalar), CURVE.n);
        if (n === 1n)
            return this;
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
    precomputeWindow(W) {
        const windows = 256 / W + 1;
        let points = [];
        let p = this;
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
    wNAF(n, affinePoint) {
        if (!affinePoint && this.equals(ExtendedPoint.BASE))
            affinePoint = Point.BASE;
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
                f = f.add(window % 2 ? precomputes[offset].negate() : precomputes[offset]);
            }
            else {
                const cached = precomputes[offset + Math.abs(wbits) - 1];
                p = p.add(wbits < 0 ? cached.negate() : cached);
            }
        }
        return [p, f];
    }
    multiply(scalar, affinePoint) {
        if (!isValidScalar(scalar))
            throw new TypeError('Point#multiply: expected number or bigint');
        const n = mod(BigInt(scalar), CURVE.n);
        return ExtendedPoint.normalizeZ(this.wNAF(n, affinePoint))[0];
    }
    toAffine(invZ = invert(this.z)) {
        const x = mod(this.x * invZ);
        const y = mod(this.y * invZ);
        return new Point(x, y);
    }
}
exports.ExtendedPoint = ExtendedPoint;
ExtendedPoint.BASE = new ExtendedPoint(CURVE.Gx, CURVE.Gy, 1n, mod(CURVE.Gx * CURVE.Gy));
ExtendedPoint.ZERO = new ExtendedPoint(0n, 1n, 1n, 0n);
const pointPrecomputes = new WeakMap();
class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }
    _setWindowSize(windowSize) {
        this._WINDOW_SIZE = windowSize;
        pointPrecomputes.delete(this);
    }
    static fromHex(hash) {
        const { d, P } = CURVE;
        const bytes = hash instanceof Uint8Array ? hash : hexToBytes(hash);
        if (bytes.length !== 32)
            throw new Error('Point.fromHex: expected 32 bytes');
        const last = bytes[31];
        const normedLast = last & ~0x80;
        const isLastByteOdd = (last & 0x80) !== 0;
        const normed = Uint8Array.from(Array.from(bytes.slice(0, 31)).concat(normedLast));
        const y = bytesToNumberLE(normed);
        if (y >= P)
            throw new Error('Point.fromHex expects hex <= Fp');
        const y2 = mod(y * y);
        const u = mod(y2 - 1n);
        const v = mod(d * y2 + 1n);
        let { isValid, value: x } = uvRatio(u, v);
        if (!isValid)
            throw new Error('Point.fromHex: invalid y coordinate');
        const isXOdd = (x & 1n) === 1n;
        if (isLastByteOdd !== isXOdd) {
            x = mod(-x);
        }
        return new Point(x, y);
    }
    static async fromPrivateKey(privateKey) {
        const privBytes = await exports.utils.sha512(normalizePrivateKey(privateKey));
        return Point.BASE.multiply(encodePrivate(privBytes));
    }
    toRawBytes() {
        const hex = numberToHex(this.y);
        const u8 = new Uint8Array(B32);
        for (let i = hex.length - 2, j = 0; j < B32 && i >= 0; i -= 2, j++) {
            u8[j] = Number.parseInt(hex[i] + hex[i + 1], 16);
        }
        const mask = this.x & 1n ? 0x80 : 0;
        u8[B32 - 1] |= mask;
        return u8;
    }
    toHex() {
        return bytesToHex(this.toRawBytes());
    }
    toX25519() {
        return mod((1n + this.y) * invert(1n - this.y));
    }
    equals(other) {
        return this.x === other.x && this.y === other.y;
    }
    negate() {
        return new Point(mod(-this.x), this.y);
    }
    add(other) {
        return ExtendedPoint.fromAffine(this).add(ExtendedPoint.fromAffine(other)).toAffine();
    }
    subtract(other) {
        return this.add(other.negate());
    }
    multiply(scalar) {
        return ExtendedPoint.fromAffine(this).multiply(scalar, this).toAffine();
    }
}
exports.Point = Point;
Point.BASE = new Point(CURVE.Gx, CURVE.Gy);
Point.ZERO = new Point(0n, 1n);
class Signature {
    constructor(r, s) {
        this.r = r;
        this.s = s;
    }
    static fromHex(hex) {
        hex = ensureBytes(hex);
        const r = Point.fromHex(hex.slice(0, 32));
        const s = bytesToNumberLE(hex.slice(32));
        if (!isWithinCurveOrder(s))
            throw new Error('Signature.fromHex expects s <= CURVE.n');
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
    }
    toHex() {
        return bytesToHex(this.toRawBytes());
    }
}
exports.Signature = Signature;
exports.SignResult = Signature;
function concatBytes(...arrays) {
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
function bytesToHex(uint8a) {
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += uint8a[i].toString(16).padStart(2, '0');
    }
    return hex;
}
function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
    }
    if (hex.length % 2)
        throw new Error('hexToBytes: received invalid unpadded hex');
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
}
function numberToHex(num) {
    const hex = num.toString(16);
    return hex.length & 1 ? `0${hex}` : hex;
}
function numberToBytesPadded(num, length = B32) {
    const hex = numberToHex(num).padStart(length * 2, '0');
    return hexToBytes(hex).reverse();
}
function edIsNegative(num) {
    return (mod(num) & 1n) === 1n;
}
function isValidScalar(num) {
    if (typeof num === 'bigint' && num > 0n)
        return true;
    if (typeof num === 'number' && num > 0 && Number.isSafeInteger(num))
        return true;
    return false;
}
function bytesToNumberLE(uint8a) {
    let value = 0n;
    for (let i = 0; i < uint8a.length; i++) {
        value += BigInt(uint8a[i]) << (8n * BigInt(i));
    }
    return value;
}
function bytes255ToNumberLE(bytes) {
    return mod(bytesToNumberLE(bytes) & (2n ** 255n - 1n));
}
function mod(a, b = CURVE.P) {
    const res = a % b;
    return res >= 0n ? res : b + res;
}
function invert(number, modulo = CURVE.P) {
    if (number === 0n || modulo <= 0n) {
        throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
    }
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
    if (gcd !== 1n)
        throw new Error('invert: does not exist');
    return mod(x, modulo);
}
function invertBatch(nums, n = CURVE.P) {
    const len = nums.length;
    const scratch = new Array(len);
    let acc = 1n;
    for (let i = 0; i < len; i++) {
        if (nums[i] === 0n)
            continue;
        scratch[i] = acc;
        acc = mod(acc * nums[i], n);
    }
    acc = invert(acc, n);
    for (let i = len - 1; i >= 0; i--) {
        if (nums[i] === 0n)
            continue;
        let tmp = mod(acc * nums[i], n);
        nums[i] = mod(acc * scratch[i], n);
        acc = tmp;
    }
    return nums;
}
function pow2(x, power) {
    const { P } = CURVE;
    let res = x;
    while (power-- > 0n) {
        res *= res;
        res %= P;
    }
    return res;
}
function pow_2_252_3(x) {
    const { P } = CURVE;
    const x2 = (x * x) % P;
    const b2 = (x2 * x) % P;
    const b4 = (pow2(b2, 2n) * b2) % P;
    const b5 = (pow2(b4, 1n) * x) % P;
    const b10 = (pow2(b5, 5n) * b5) % P;
    const b20 = (pow2(b10, 10n) * b10) % P;
    const b40 = (pow2(b20, 20n) * b20) % P;
    const b80 = (pow2(b40, 40n) * b40) % P;
    const b160 = (pow2(b80, 80n) * b80) % P;
    const b240 = (pow2(b160, 80n) * b80) % P;
    const b250 = (pow2(b240, 10n) * b10) % P;
    const pow_p_5_8 = (pow2(b250, 2n) * x) % P;
    return pow_p_5_8;
}
function uvRatio(u, v) {
    const v3 = mod(v * v * v);
    const v7 = mod(v3 * v3 * v);
    let x = mod(u * v3 * pow_2_252_3(u * v7));
    const vx2 = mod(v * x * x);
    const root1 = x;
    const root2 = mod(x * SQRT_M1);
    const useRoot1 = vx2 === u;
    const useRoot2 = vx2 === mod(-u);
    const noRoot = vx2 === mod(-u * SQRT_M1);
    if (useRoot1)
        x = root1;
    if (useRoot2 || noRoot)
        x = root2;
    if (edIsNegative(x))
        x = mod(-x);
    return { isValid: useRoot1 || useRoot2, value: x };
}
function invertSqrt(number) {
    return uvRatio(1n, number);
}
async function sha512ToNumberLE(...args) {
    const messageArray = concatBytes(...args);
    const hash = await exports.utils.sha512(messageArray);
    const value = bytesToNumberLE(hash);
    return mod(value, CURVE.n);
}
function keyPrefix(privateBytes) {
    return privateBytes.slice(B32);
}
function encodePrivate(privateBytes) {
    const last = B32 - 1;
    const head = privateBytes.slice(0, B32);
    head[0] &= 248;
    head[last] &= 127;
    head[last] |= 64;
    return mod(bytesToNumberLE(head), CURVE.n);
}
function equalBytes(b1, b2) {
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
function ensureBytes(hash) {
    return hash instanceof Uint8Array ? hash : hexToBytes(hash);
}
function isWithinCurveOrder(num) {
    return 0 < num && num < CURVE.n;
}
function normalizePrivateKey(key) {
    let num;
    if (typeof key === 'bigint' || (typeof key === 'number' && Number.isSafeInteger(key))) {
        num = BigInt(key);
        if (num < 0n || num > 2n ** 256n)
            throw new Error('Expected 32 bytes of private key');
        key = num.toString(16).padStart(B32 * 2, '0');
    }
    if (typeof key === 'string') {
        if (key.length !== 64)
            throw new Error('Expected 32 bytes of private key');
        return hexToBytes(key);
    }
    else if (key instanceof Uint8Array) {
        if (key.length !== 32)
            throw new Error('Expected 32 bytes of private key');
        return key;
    }
    else {
        throw new TypeError('Expected valid private key');
    }
}
async function getPublicKey(privateKey) {
    const key = await Point.fromPrivateKey(privateKey);
    return typeof privateKey === 'string' ? key.toHex() : key.toRawBytes();
}
exports.getPublicKey = getPublicKey;
async function sign(hash, privateKey) {
    const privBytes = await exports.utils.sha512(normalizePrivateKey(privateKey));
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
exports.sign = sign;
async function verify(signature, hash, publicKey) {
    hash = ensureBytes(hash);
    if (!(publicKey instanceof Point))
        publicKey = Point.fromHex(publicKey);
    if (!(signature instanceof Signature))
        signature = Signature.fromHex(signature);
    const hs = await sha512ToNumberLE(signature.r.toRawBytes(), publicKey.toRawBytes(), hash);
    const Ph = ExtendedPoint.fromAffine(publicKey).multiplyUnsafe(hs);
    const Gs = ExtendedPoint.BASE.multiply(signature.s);
    const RPh = ExtendedPoint.fromAffine(signature.r).add(Ph);
    return RPh.subtract(Gs).multiplyUnsafe(8n).equals(ExtendedPoint.ZERO);
}
exports.verify = verify;
Point.BASE._setWindowSize(8);
const crypto = (() => {
    const webCrypto = typeof self === 'object' && 'crypto' in self ? self.crypto : undefined;
    const nodeRequire = typeof module !== 'undefined' &&
        typeof module.require === 'function' &&
        module.require.bind(module);
    return {
        node: nodeRequire && !webCrypto ? nodeRequire('crypto') : undefined,
        web: webCrypto,
    };
})();
exports.utils = {
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
    randomBytes: (bytesLength = 32) => {
        if (crypto.web) {
            return crypto.web.getRandomValues(new Uint8Array(bytesLength));
        }
        else if (crypto.node) {
            const { randomBytes } = crypto.node;
            return new Uint8Array(randomBytes(bytesLength).buffer);
        }
        else {
            throw new Error("The environment doesn't have randomBytes function");
        }
    },
    randomPrivateKey: () => {
        let i = 1024;
        while (i--) {
            const b32 = exports.utils.randomBytes(32);
            const num = bytesToNumberLE(b32);
            if (num > 1n && num < CURVE.n)
                return b32;
        }
        throw new Error('Valid private key was not found in 1024 iterations. PRNG is broken');
    },
    sha512: async (message) => {
        if (crypto.web) {
            const buffer = await crypto.web.subtle.digest('SHA-512', message.buffer);
            return new Uint8Array(buffer);
        }
        else if (crypto.node) {
            return Uint8Array.from(crypto.node.createHash('sha512').update(message).digest());
        }
        else {
            throw new Error("The environment doesn't have sha512 function");
        }
    },
    precompute(windowSize = 8, point = Point.BASE) {
        const cached = point.equals(Point.BASE) ? point : new Point(point.x, point.y);
        cached._setWindowSize(windowSize);
        cached.multiply(1n);
        return cached;
    },
};

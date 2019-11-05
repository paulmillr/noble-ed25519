"use strict";
/*! noble-ristretto255 - MIT License (c) Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
const mask64Bits = (1n << 64n) - 1n;
const low51bitMask = (1n << 51n) - 1n;
class FieldElement {
    constructor(value) {
        this.value = FieldElement.mod(value, FieldElement.P);
    }
    static load8(input, padding = 0) {
        return (BigInt(input[0 + padding]) |
            (BigInt(input[1 + padding]) << 8n) |
            (BigInt(input[2 + padding]) << 16n) |
            (BigInt(input[3 + padding]) << 24n) |
            (BigInt(input[4 + padding]) << 32n) |
            (BigInt(input[5 + padding]) << 40n) |
            (BigInt(input[6 + padding]) << 48n) |
            (BigInt(input[7 + padding]) << 56n));
    }
    static fromBytes(bytes) {
        const octet1 = this.load8(bytes, 0) & low51bitMask;
        const octet2 = (this.load8(bytes, 6) >> 3n) & low51bitMask;
        const octet3 = (this.load8(bytes, 12) >> 6n) & low51bitMask;
        const octet4 = (this.load8(bytes, 19) >> 1n) & low51bitMask;
        const octet5 = (this.load8(bytes, 24) >> 12n) & low51bitMask;
        return new FieldElement(octet1 +
            (octet2 << 51n) +
            (octet3 << 102n) +
            (octet4 << 153n) +
            (octet5 << 204n));
    }
    static one() {
        return new FieldElement(1n);
    }
    static zero() {
        return new FieldElement(0n);
    }
    static mod(a, b) {
        const res = a % b;
        return res >= 0 ? res : b + res;
    }
    toBytesBE(length = 0) {
        let hex = this.value.toString(16);
        hex = hex.length & 1 ? `0${hex}` : hex;
        hex = hex.padStart(length * 2, "0");
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
    equals(other) {
        return this.value === other.value;
    }
    isNegative() {
        const bytes = this.toBytesLE();
        return Boolean(bytes[0] & 1);
    }
    isZero() {
        return this.value === 0n;
    }
    add(other) {
        return new FieldElement(this.value + other.value);
    }
    subtract(other) {
        return new FieldElement(this.value - other.value);
    }
    div(other) {
        return new FieldElement(this.value / other.value);
    }
    multiply(other) {
        return new FieldElement(this.value * other.value);
    }
    pow(power) {
        let res = FieldElement.one();
        let x = this;
        while (power > 0) {
            if (power & 1n) {
                res = res.multiply(x);
            }
            power >>= 1n;
            x = x.square();
        }
        return res;
    }
    pow2k(power) {
        let res = this;
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
    pow22501() {
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
    powP58() {
        const [t19] = this.pow22501();
        return t19.pow2k(2n).multiply(this);
    }
    select(other, choice) {
        return choice ? this : other;
    }
    condNegative(choice) {
        return this.negative().select(this, choice);
    }
    condSwap(other, choice) {
        choice = BigInt(choice);
        const mask = choice !== 0n ? mask64Bits : choice;
        const tmp = mask & (this.value ^ other.value);
        return [
            new FieldElement(this.value ^ tmp),
            new FieldElement(other.value ^ tmp)
        ];
    }
    sqrtRatio(v) {
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
    invertSqrt() {
        return FieldElement.one().sqrtRatio(this);
    }
}
exports.FieldElement = FieldElement;
FieldElement.P = 2n ** 255n - 19n;
FieldElement.D = new FieldElement(37095705934669439343138083508754565189542113879843219016388785533085940283555n);
FieldElement.D2 = new FieldElement(16295367250680780974490674513165176452449235426866156013048779062215315747161n);
FieldElement.SQRT_M1 = new FieldElement(19681161376707505956807079304988542015446066515923890162744021073123829784752n);
FieldElement.INVSQRT_A_MINUS_D = new FieldElement(54469307008909316920995813868745141605393597292927456921205312896311721017578n);
FieldElement.SQRT_AD_MINUS_ONE = new FieldElement(25063068953384623474111414158702152701244531502492656460079210482610430750235n);
FieldElement.PRIME_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;
exports.P = FieldElement.P;
exports.PRIME_ORDER = FieldElement.PRIME_ORDER;
class ProjectiveP1xP1 {
    constructor(x, y, z, T) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.T = T;
    }
    static zero() {
        return new ProjectiveP1xP1(FieldElement.zero(), FieldElement.one(), FieldElement.one(), FieldElement.one());
    }
}
exports.ProjectiveP1xP1 = ProjectiveP1xP1;
class ProjectiveP2 {
    constructor(x, y, z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
    static fromP1xP1(point) {
        return new ProjectiveP2(point.x.multiply(point.T), point.y.multiply(point.T), point.z.multiply(point.T));
    }
    static fromP3(point) {
        return new ProjectiveP2(point.x, point.y, point.z);
    }
    static zero() {
        return new ProjectiveP2(FieldElement.zero(), FieldElement.one(), FieldElement.one());
    }
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
exports.ProjectiveP2 = ProjectiveP2;
class ProjectiveP3 {
    constructor(x, y, z, T) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.T = T;
    }
    static fromP1xP1(point) {
        return new ProjectiveP3(point.x.multiply(point.T), point.y.multiply(point.z), point.z.multiply(point.T), point.x.multiply(point.y));
    }
    static fromP2(point) {
        return new ProjectiveP3(point.x.multiply(point.z), point.y.multiply(point.z), point.z.square(), point.x.multiply(point.y));
    }
    static one() {
        return new ProjectiveP3(FieldElement.zero(), FieldElement.one(), FieldElement.one(), FieldElement.zero());
    }
    toProjectiveNielsPoint() {
        return new ProjectiveP3(this.y.add(this.x), this.y.subtract(this.x), this.z, this.T.multiply(FieldElement.D2));
    }
    toExtendedProjective() {
        return new ProjectiveP3(this.x.multiply(this.z), this.y.multiply(this.z), this.z.multiply(this.z), this.x.multiply(this.y));
    }
    toExtendedCompleted() {
        return new ProjectiveP3(this.x.multiply(this.T), this.y.multiply(this.z), this.z.multiply(this.T), this.x.multiply(this.y));
    }
    addCached(other) {
        const yPlusX = this.y.add(this.x);
        const yMinusX = this.y.subtract(this.x);
        const PP = yPlusX.multiply(other.yPlusX);
        const MM = yMinusX.multiply(other.yMinusX);
        const TT2 = this.T.multiply(other.T2d);
        const ZZ = this.z.multiply(other.z);
        const ZZ2 = ZZ.add(ZZ);
        return new ProjectiveP1xP1(PP.subtract(MM), PP.add(MM), ZZ2.add(TT2), ZZ2.subtract(TT2));
    }
    subtractCached(other) {
        const yPlusX = this.y.add(this.x);
        const yMinusX = this.y.subtract(this.x);
        const PP = yPlusX.multiply(other.yMinusX);
        const MM = yMinusX.multiply(other.yPlusX);
        const TT2 = this.T.multiply(other.T2d);
        const ZZ = this.z.multiply(other.z);
        const ZZ2 = ZZ.add(ZZ);
        return new ProjectiveP1xP1(PP.subtract(MM), PP.add(MM), ZZ2.subtract(TT2), ZZ2.add(TT2));
    }
    addAffine(other) {
        const yPlusX = this.y.add(this.x);
        const yMinusX = this.y.subtract(this.x);
        const PP = yPlusX.multiply(other.yPlusX);
        const MM = yMinusX.multiply(other.yMinusX);
        const TT2 = this.T.multiply(other.T2d);
        const ZZ = this.z.multiply(this.z);
        const ZZ2 = ZZ.add(ZZ);
        return new ProjectiveP1xP1(PP.subtract(MM), PP.add(MM), ZZ2.add(TT2), ZZ2.subtract(TT2));
    }
    subtractAffine(other) {
        const yPlusX = this.y.add(this.x);
        const yMinusX = this.y.subtract(this.x);
        const PP = yPlusX.multiply(other.yMinusX);
        const MM = yMinusX.multiply(other.yPlusX);
        const TT2 = this.T.multiply(other.T2d);
        const ZZ = this.z.multiply(this.z);
        const ZZ2 = ZZ.add(ZZ);
        return new ProjectiveP1xP1(PP.subtract(MM), PP.add(MM), ZZ2.subtract(TT2), ZZ2.add(TT2));
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
        const x2 = this.x.square();
        const y2 = this.y.square();
        const z2 = this.z.square();
        const xPlusY2 = this.x.add(this.y).square();
        const y2PlusX2 = y2.add(x2);
        const y2MinusX2 = y2.subtract(x2);
        return new ProjectiveP3(xPlusY2.subtract(y2MinusX2), y2PlusX2, y2MinusX2, z2.subtract(y2MinusX2));
    }
    negative() {
        return new ProjectiveP3(this.x.negative(), this.y, this.z, this.T.negative());
    }
    multiply(n) {
        let q = ProjectiveP3.one();
        for (let db = this; n > 0n; n >>= 1n, db = db.double()) {
            if ((n & 1n) === 1n) {
                q = q.add(db);
            }
        }
        return q;
    }
    equals(other) {
        const t1 = this.x.multiply(other.z);
        const t2 = other.x.multiply(this.z);
        const t3 = this.y.multiply(other.z);
        const t4 = other.y.multiply(this.z);
        return t1.equals(t2) && t3.equals(t4);
    }
}
exports.ProjectiveP3 = ProjectiveP3;
class ProjectiveCached {
    constructor(yPlusX, yMinusX, z, T2d) {
        this.yPlusX = yPlusX;
        this.yMinusX = yMinusX;
        this.z = z;
        this.T2d = T2d;
    }
    static one() {
        return new ProjectiveCached(FieldElement.one(), FieldElement.one(), FieldElement.one(), FieldElement.zero());
    }
    static fromP3(point) {
        return new ProjectiveCached(point.y.add(point.x), point.y.subtract(point.x), point.z, point.T.multiply(FieldElement.D2));
    }
    select(other, cond) {
        const yPlusX = this.yPlusX.select(other.yPlusX, cond);
        const yMinusX = this.yMinusX.select(other.yMinusX, cond);
        const z = this.z.select(other.z, cond);
        const T2d = this.T2d.select(other.T2d, cond);
        return new ProjectiveCached(yPlusX, yMinusX, z, T2d);
    }
    condNegative(cond) {
        const [yPlusX, yMinusX] = this.yPlusX.condSwap(this.yMinusX, cond);
        const T2d = this.T2d.condNegative(cond);
        return new ProjectiveCached(yPlusX, yMinusX, this.z, T2d);
    }
}
exports.ProjectiveCached = ProjectiveCached;
class AffineCached {
    constructor(yPlusX, yMinusX, T2d) {
        this.yPlusX = yPlusX;
        this.yMinusX = yMinusX;
        this.T2d = T2d;
    }
    static fromP3(point) {
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
    select(other, cond) {
        const yPlusX = this.yPlusX.select(other.yPlusX, cond);
        const yMinusX = this.yMinusX.select(other.yMinusX, cond);
        const T2d = this.T2d.select(other.T2d, cond);
        return new AffineCached(yPlusX, yMinusX, T2d);
    }
    condNegative(cond) {
        const [yPlusX, yMinusX] = this.yPlusX.condSwap(this.yMinusX, cond);
        const T2d = this.T2d.condNegative(cond);
        return new AffineCached(yPlusX, yMinusX, T2d);
    }
}
exports.AffineCached = AffineCached;
if (typeof window == "object" && "crypto" in window) {
    exports.sha512 = async (message) => {
        const buffer = await window.crypto.subtle.digest("SHA-512", message.buffer);
        return new Uint8Array(buffer);
    };
}
else if (typeof process === "object" && "node" in process.versions) {
    const { createHash } = require("crypto");
    exports.sha512 = async (message) => {
        const hash = createHash("sha512");
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
    if (typeof bytes === "string") {
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
    if (typeof num === "string") {
        return fromHexBE(num);
    }
    if (typeof num === "number") {
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
function concatTypedArrays(...args) {
    const result = new Uint8Array(args.reduce((a, arr) => a + arr.length, 0));
    for (let i = 0, pad = 0; i < args.length; i++) {
        const arr = args[i];
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
    static one() {
        return new RistrettoPoint(ProjectiveP3.one());
    }
    static fromHash(hash) {
        const r1 = FieldElement.fromBytes(hash.slice(0, ENCODING_LENGTH));
        const R1 = this.elligatorRistrettoFlavor(r1);
        const r2 = FieldElement.fromBytes(hash.slice(ENCODING_LENGTH, ENCODING_LENGTH * 2));
        const R2 = this.elligatorRistrettoFlavor(r2);
        return new RistrettoPoint(R1.add(R2));
    }
    static elligatorRistrettoFlavor(r0) {
        const one = FieldElement.one();
        const oneMinusDSq = one.subtract(FieldElement.D.square());
        const dMinusOneSq = (FieldElement.D.subtract(one)).square();
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
        const NT = c.multiply(r.subtract(one)).multiply(dMinusOneSq).subtract(D);
        const sSquared = S.square();
        const projective = new ProjectiveP3(S.add(S).multiply(D), FieldElement.one().subtract(sSquared), NT.multiply(FieldElement.SQRT_AD_MINUS_ONE), FieldElement.one().add(sSquared));
        return projective.toExtendedCompleted();
    }
    static fromBytes(bytes) {
        const s = FieldElement.fromBytes(bytes);
        const sEncodingIsCanonical = isBytesEquals(s.toBytesLE(ENCODING_LENGTH), bytes);
        const sIsNegative = s.isNegative();
        if (!sEncodingIsCanonical || sIsNegative) {
            throw new Error("Cannot convert bytes to Ristretto Point");
        }
        const one = FieldElement.one();
        const s2 = s.square();
        const u1 = one.subtract(s2);
        const u2 = one.add(s2);
        const squaredU2 = u2.square();
        const v = u1.square().multiply(FieldElement.D.negative()).subtract(squaredU2);
        const { isNotZeroSquare, value: I } = v.multiply(squaredU2).invertSqrt();
        const Dx = I.multiply(u2);
        const Dy = I.multiply(Dx).multiply(v);
        let x = s.add(s).multiply(Dx);
        const xIsNegative = BigInt(x.isNegative());
        x = x.condNegative(xIsNegative);
        const y = u1.multiply(Dy);
        const t = x.multiply(y);
        if (!isNotZeroSquare || t.isNegative() || y.isZero()) {
            throw new Error("Cannot convert bytes to Ristretto Point");
        }
        return new RistrettoPoint(new ProjectiveP3(x, y, one, t));
    }
    toBytes() {
        let { x, y, z, T } = this.point;
        const u1 = z.add(y).multiply(z.subtract(y));
        const u2 = x.multiply(y);
        const { value: invsqrt } = u2.square().multiply(u1).invertSqrt();
        const i1 = invsqrt.multiply(u1);
        const i2 = invsqrt.multiply(u2);
        const invertedZ = i1.multiply(i2).multiply(T);
        let invertedDenominator = i2;
        const iX = x.multiply(FieldElement.SQRT_M1);
        const iY = y.multiply(FieldElement.SQRT_M1);
        const enchantedDenominator = i1.multiply(FieldElement.INVSQRT_A_MINUS_D);
        const isRotated = BigInt(T.multiply(invertedZ).isNegative());
        x = iY.select(x, isRotated);
        y = iX.select(y, isRotated);
        invertedDenominator = enchantedDenominator.select(i2, isRotated);
        const yIsNegative = BigInt(x.multiply(invertedZ).isNegative());
        y = y.condNegative(yIsNegative);
        let s = z.subtract(y).multiply(invertedDenominator);
        const sIsNegative = BigInt(s.isNegative());
        s = s.condNegative(sIsNegative);
        return s.toBytesLE(ENCODING_LENGTH);
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
exports.BASE_POINT = new RistrettoPoint(new ProjectiveP3(new FieldElement(15112221349535400772501151409588531511454012693041857206046113283949847762202n), new FieldElement(46316835694926478169428394003475163141307993866256225615783033603165251855960n), new FieldElement(1n), new FieldElement(46827403850823179245072216630277197565144205554125654976674165829533817101731n)));

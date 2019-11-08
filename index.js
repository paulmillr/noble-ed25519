"use strict";
/*! noble-ed25519 - MIT License (c) Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
const ENCODING_LENGTH = 32;
const A = -1n;
const C = 1n;
exports.P = 2n ** 255n - 19n;
exports.PRIME_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;
const d = -121665n * inversion(121666n);
const I = powMod(2n, (exports.P - 1n) / 4n, exports.P);
class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }
    static fromHex(hash) {
        const bytes = hash instanceof Uint8Array ? hash : hexToArray(hash);
        const len = bytes.length - 1;
        const normedLast = bytes[len] & ~0x80;
        const normed = new Uint8Array([...bytes.slice(0, -1), normedLast]);
        const y = arrayToNumberLE(normed);
        const sqrY = y * y;
        const sqrX = mod((sqrY - C) * inversion(C * d * sqrY - A), exports.P);
        let x = powMod(sqrX, (exports.P + 3n) / 8n, exports.P);
        const isLastByteOdd = (bytes[len] & 0x80) !== 0;
        if (mod(x * x - sqrX, exports.P) !== 0n) {
            x = mod(x * I, exports.P);
        }
        const isXOdd = (x & 1n) === 1n;
        if (isLastByteOdd !== isXOdd) {
            x = mod(-x, exports.P);
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
        let hex = "";
        for (let i = 0; i < bytes.length; i++) {
            const value = bytes[i].toString(16);
            hex = `${hex}${value.length > 1 ? value : `0${value}`}`;
        }
        return hex;
    }
    reverseY() {
        return new Point(this.x, -this.y);
    }
    add(p2) {
        const p1 = this;
        const x = (p1.x * p2.y + p2.x * p1.y) *
            inversion(1n + d * p1.x * p2.x * p1.y * p2.y);
        const y = (p1.y * p2.y + p1.x * p2.x) *
            inversion(1n - d * p1.x * p2.x * p1.y * p2.y);
        return new Point(mod(x, exports.P), mod(y, exports.P));
    }
    subtract(p2) {
        return this.add(p2.reverseY());
    }
    multiply(n) {
        let q = new Point(0n, 1n);
        for (let db = this; n > 0n; n >>= 1n, db = db.add(db)) {
            if ((n & 1n) === 1n) {
                q = q.add(db);
            }
        }
        return q;
    }
}
exports.Point = Point;
exports.BASE_POINT = new Point(15112221349535400772501151409588531511454012693041857206046113283949847762202n, 46316835694926478169428394003475163141307993866256225615783033603165251855960n);
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
        const numberBytes = numberToUint8Array(this.s).reverse();
        const sBytes = new Uint8Array(ENCODING_LENGTH);
        sBytes.set(numberBytes);
        const bytes = concatTypedArrays(this.r.encode(), sBytes);
        let hex = "";
        for (let i = 0; i < bytes.length; i++) {
            const value = bytes[i].toString(16);
            hex = `${hex}${value.length > 1 ? value : `0${value}`}`;
        }
        return hex;
    }
}
exports.SignResult = SignResult;
let sha512;
if (typeof window == "object" && "crypto" in window) {
    sha512 = async (message) => {
        const buffer = await window.crypto.subtle.digest("SHA-512", message.buffer);
        return new Uint8Array(buffer);
    };
}
else if (typeof process === "object" && "node" in process.versions) {
    const { createHash } = require("crypto");
    sha512 = async (message) => {
        const hash = createHash("sha512");
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
function numberToUint8Array(num, padding) {
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
    return BigInt(`0x${hex}`);
}
function arrayToNumberBE(bytes) {
    let value = 0n;
    for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
        value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
    }
    return value;
}
async function hashNumber(...args) {
    const messageArray = concatTypedArrays(...args);
    const hash = await sha512(messageArray);
    const value = arrayToNumberLE(hash);
    return mod(value, exports.PRIME_ORDER);
}
function getPrivateBytes(privateKey) {
    return sha512(privateKey instanceof Uint8Array
        ? privateKey
        : numberToUint8Array(privateKey, 64));
}
function keyPrefix(privateBytes) {
    return privateBytes.slice(ENCODING_LENGTH);
}
function mod(a, b) {
    const res = a % b;
    return res >= 0 ? res : b + res;
}
function inversion(num) {
    return powMod(num, exports.P - 2n, exports.P);
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
        res = arrayToNumberBE(privateKey);
    }
    else if (typeof privateKey === "string") {
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
    if (typeof privateKey === "string") {
        return point.toHex();
    }
    return point;
}
function normalizeSignature(signature) {
    return signature instanceof SignResult
        ? signature
        : SignResult.fromHex(signature);
}
function normalizeHash(hash) {
    return hash instanceof Uint8Array ? hash : hexToArray(hash);
}
async function getPublicKey(privateKey) {
    const multiplier = normalizePrivateKey(privateKey);
    const privateBytes = await getPrivateBytes(multiplier);
    const privateInt = encodePrivate(privateBytes);
    const publicKey = exports.BASE_POINT.multiply(privateInt);
    return normalizePoint(publicKey, privateKey);
}
exports.getPublicKey = getPublicKey;
async function sign(hash, privateKey) {
    const message = normalizeHash(hash);
    privateKey = normalizePrivateKey(privateKey);
    const publicKey = await getPublicKey(privateKey);
    const privateBytes = await getPrivateBytes(privateKey);
    const privatePrefix = keyPrefix(privateBytes);
    const r = await hashNumber(privatePrefix, message);
    const R = exports.BASE_POINT.multiply(r);
    const h = await hashNumber(R.encode(), publicKey.encode(), message);
    const S = mod(r + h * encodePrivate(privateBytes), exports.PRIME_ORDER);
    const signature = new SignResult(R, S).toHex();
    return hash instanceof Uint8Array ? hexToArray(signature) : signature;
}
exports.sign = sign;
async function verify(signature, hash, publicKey) {
    hash = normalizeHash(hash);
    publicKey = normalizePublicKey(publicKey);
    signature = normalizeSignature(signature);
    const h = await hashNumber(signature.r.encode(), publicKey.encode(), hash);
    const S = exports.BASE_POINT.multiply(signature.s);
    const R = signature.r.add(publicKey.multiply(h));
    return S.x === R.x && S.y === R.y;
}
exports.verify = verify;

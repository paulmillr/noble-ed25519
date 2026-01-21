"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyAsync = exports.verify = exports.utils = exports.signAsync = exports.sign = exports.Point = exports.keygenAsync = exports.keygen = exports.hashes = exports.hash = exports.getPublicKeyAsync = exports.getPublicKey = exports.etc = void 0;
/*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
/**
 * 5KB JS implementation of ed25519 EdDSA signatures.
 * Compliant with RFC8032, FIPS 186-5 & ZIP215.
 * @module
 * @example
 * ```js
import * as ed from '@noble/ed25519';
(async () => {
  const secretKey = ed.utils.randomSecretKey();
  const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
  const pubKey = await ed.getPublicKeyAsync(secretKey); // Sync methods are also present
  const signature = await ed.signAsync(message, secretKey);
  const isValid = await ed.verifyAsync(signature, message, pubKey);
})();
```
 */
/**
 * Curve params. ed25519 is twisted edwards curve. Equation is −x² + y² = -a + dx²y².
 * * P = `2n**255n - 19n` // field over which calculations are done
 * * N = `2n**252n + 27742317777372353535851937790883648493n` // group order, amount of curve points
 * * h = 8 // cofactor
 * * a = `Fp.create(BigInt(-1))` // equation param
 * * d = -121665/121666 a.k.a. `Fp.neg(121665 * Fp.inv(121666))` // equation param
 * * Gx, Gy are coordinates of Generator / base point
 */
var ed25519_CURVE = {
    p: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn,
    n: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
    h: 8n,
    a: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffecn,
    d: 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n,
    Gx: 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an,
    Gy: 0x6666666666666666666666666666666666666666666666666666666666666658n,
};
var P = ed25519_CURVE.p, N = ed25519_CURVE.n, Gx = ed25519_CURVE.Gx, Gy = ed25519_CURVE.Gy, _a = ed25519_CURVE.a, _d = ed25519_CURVE.d, h = ed25519_CURVE.h;
var L = 32; // field / group byte length
var L2 = 64;
// Helpers and Precomputes sections are reused between libraries
// ## Helpers
// ----------
var captureTrace = function () {
    var args = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        args[_i] = arguments[_i];
    }
    if ('captureStackTrace' in Error && typeof Error.captureStackTrace === 'function') {
        Error.captureStackTrace.apply(Error, args);
    }
};
var err = function (message) {
    if (message === void 0) { message = ''; }
    var e = new Error(message);
    captureTrace(e, err);
    throw e;
};
var isBig = function (n) { return typeof n === 'bigint'; }; // is big integer
var isStr = function (s) { return typeof s === 'string'; }; // is string
var isBytes = function (a) {
    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
};
/** Asserts something is Uint8Array. */
var abytes = function (value, length, title) {
    if (title === void 0) { title = ''; }
    var bytes = isBytes(value);
    var len = value === null || value === void 0 ? void 0 : value.length;
    var needsLen = length !== undefined;
    if (!bytes || (needsLen && len !== length)) {
        var prefix = title && "\"".concat(title, "\" ");
        var ofLen = needsLen ? " of length ".concat(length) : '';
        var got = bytes ? "length=".concat(len) : "type=".concat(typeof value);
        err(prefix + 'expected Uint8Array' + ofLen + ', got ' + got);
    }
    return value;
};
/** create Uint8Array */
var u8n = function (len) { return new Uint8Array(len); };
var u8fr = function (buf) { return Uint8Array.from(buf); };
var padh = function (n, pad) { return n.toString(16).padStart(pad, '0'); };
var bytesToHex = function (b) {
    return Array.from(abytes(b))
        .map(function (e) { return padh(e, 2); })
        .join('');
};
var C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 }; // ASCII characters
var _ch = function (ch) {
    if (ch >= C._0 && ch <= C._9)
        return ch - C._0; // '2' => 50-48
    if (ch >= C.A && ch <= C.F)
        return ch - (C.A - 10); // 'B' => 66-(65-10)
    if (ch >= C.a && ch <= C.f)
        return ch - (C.a - 10); // 'b' => 98-(97-10)
    return;
};
var hexToBytes = function (hex) {
    var e = 'hex invalid';
    if (!isStr(hex))
        return err(e);
    var hl = hex.length;
    var al = hl / 2;
    if (hl % 2)
        return err(e);
    var array = u8n(al);
    for (var ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        // treat each char as ASCII
        var n1 = _ch(hex.charCodeAt(hi)); // parse first char, multiply it by 16
        var n2 = _ch(hex.charCodeAt(hi + 1)); // parse second char
        if (n1 === undefined || n2 === undefined)
            return err(e);
        array[ai] = n1 * 16 + n2; // example: 'A9' => 10*16 + 9
    }
    return array;
};
var cr = function () { return globalThis === null || globalThis === void 0 ? void 0 : globalThis.crypto; }; // WebCrypto is available in all modern environments
var subtle = function () { var _b, _c; return (_c = (_b = cr()) === null || _b === void 0 ? void 0 : _b.subtle) !== null && _c !== void 0 ? _c : err('crypto.subtle must be defined, consider polyfill'); };
// prettier-ignore
var concatBytes = function () {
    var arrs = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        arrs[_i] = arguments[_i];
    }
    var r = u8n(arrs.reduce(function (sum, a) { return sum + abytes(a).length; }, 0)); // create u8a of summed length
    var pad = 0; // walk through each array,
    arrs.forEach(function (a) { r.set(a, pad); pad += a.length; }); // ensure they have proper type
    return r;
};
/** WebCrypto OS-level CSPRNG (random number generator). Will throw when not available. */
var randomBytes = function (len) {
    if (len === void 0) { len = L; }
    var c = cr();
    return c.getRandomValues(u8n(len));
};
var big = BigInt;
var assertRange = function (n, min, max, msg) {
    if (msg === void 0) { msg = 'bad number: out of range'; }
    return (isBig(n) && min <= n && n < max ? n : err(msg));
};
/** modular division */
var M = function (a, b) {
    if (b === void 0) { b = P; }
    var r = a % b;
    return r >= 0n ? r : b + r;
};
var modN = function (a) { return M(a, N); };
/** Modular inversion using euclidean GCD (non-CT). No negative exponent for now. */
// prettier-ignore
var invert = function (num, md) {
    if (num === 0n || md <= 0n)
        err('no inverse n=' + num + ' mod=' + md);
    var a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
    while (a !== 0n) {
        var q = b / a, r = b % a;
        var m = x - u * q, n = y - v * q;
        b = a, a = r, x = u, y = v, u = m, v = n;
    }
    return b === 1n ? M(x, md) : err('no inverse'); // b is gcd at this point
};
var callHash = function (name) {
    // @ts-ignore
    var fn = hashes[name];
    if (typeof fn !== 'function')
        err('hashes.' + name + ' not set');
    return fn;
};
var hash = function (msg) { return callHash('sha512')(msg); };
exports.hash = hash;
var apoint = function (p) { return (p instanceof Point ? p : err('Point expected')); };
// ## End of Helpers
// -----------------
var B256 = Math.pow(2n, 256n);
/** Point in XYZT extended coordinates. */
var Point = /** @class */ (function () {
    function Point(X, Y, Z, T) {
        var max = B256;
        this.X = assertRange(X, 0n, max);
        this.Y = assertRange(Y, 0n, max);
        this.Z = assertRange(Z, 1n, max);
        this.T = assertRange(T, 0n, max);
        Object.freeze(this);
    }
    Point.CURVE = function () {
        return ed25519_CURVE;
    };
    Point.fromAffine = function (p) {
        return new Point(p.x, p.y, 1n, M(p.x * p.y));
    };
    /** RFC8032 5.1.3: Uint8Array to Point. */
    Point.fromBytes = function (hex, zip215) {
        if (zip215 === void 0) { zip215 = false; }
        var d = _d;
        // Copy array to not mess it up.
        var normed = u8fr(abytes(hex, L));
        // adjust first LE byte = last BE byte
        var lastByte = hex[31];
        normed[31] = lastByte & ~0x80;
        var y = bytesToNumLE(normed);
        // zip215=true:           0 <= y < 2^256
        // zip215=false, RFC8032: 0 <= y < 2^255-19
        var max = zip215 ? B256 : P;
        assertRange(y, 0n, max);
        var y2 = M(y * y); // y²
        var u = M(y2 - 1n); // u=y²-1
        var v = M(d * y2 + 1n); // v=dy²+1
        var _b = uvRatio(u, v), isValid = _b.isValid, x = _b.value; // (uv³)(uv⁷)^(p-5)/8; square root
        if (!isValid)
            err('bad point: y not sqrt'); // not square root: bad point
        var isXOdd = (x & 1n) === 1n; // adjust sign of x coordinate
        var isLastByteOdd = (lastByte & 0x80) !== 0; // x_0, last bit
        if (!zip215 && x === 0n && isLastByteOdd)
            err('bad point: x==0, isLastByteOdd'); // x=0, x_0=1
        if (isLastByteOdd !== isXOdd)
            x = M(-x);
        return new Point(x, y, 1n, M(x * y)); // Z=1, T=xy
    };
    Point.fromHex = function (hex, zip215) {
        return Point.fromBytes(hexToBytes(hex), zip215);
    };
    Object.defineProperty(Point.prototype, "x", {
        get: function () {
            return this.toAffine().x;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(Point.prototype, "y", {
        get: function () {
            return this.toAffine().y;
        },
        enumerable: false,
        configurable: true
    });
    /** Checks if the point is valid and on-curve. */
    Point.prototype.assertValidity = function () {
        var a = _a;
        var d = _d;
        var p = this;
        if (p.is0())
            return err('bad point: ZERO'); // TODO: optimize, with vars below?
        // Equation in affine coordinates: ax² + y² = 1 + dx²y²
        // Equation in projective coordinates (X/Z, Y/Z, Z):  (aX² + Y²)Z² = Z⁴ + dX²Y²
        var X = p.X, Y = p.Y, Z = p.Z, T = p.T;
        var X2 = M(X * X); // X²
        var Y2 = M(Y * Y); // Y²
        var Z2 = M(Z * Z); // Z²
        var Z4 = M(Z2 * Z2); // Z⁴
        var aX2 = M(X2 * a); // aX²
        var left = M(Z2 * M(aX2 + Y2)); // (aX² + Y²)Z²
        var right = M(Z4 + M(d * M(X2 * Y2))); // Z⁴ + dX²Y²
        if (left !== right)
            return err('bad point: equation left != right (1)');
        // In Extended coordinates we also have T, which is x*y=T/Z: check X*Y == Z*T
        var XY = M(X * Y);
        var ZT = M(Z * T);
        if (XY !== ZT)
            return err('bad point: equation left != right (2)');
        return this;
    };
    /** Equality check: compare points P&Q. */
    Point.prototype.equals = function (other) {
        var _b = this, X1 = _b.X, Y1 = _b.Y, Z1 = _b.Z;
        var _c = apoint(other), X2 = _c.X, Y2 = _c.Y, Z2 = _c.Z; // checks class equality
        var X1Z2 = M(X1 * Z2);
        var X2Z1 = M(X2 * Z1);
        var Y1Z2 = M(Y1 * Z2);
        var Y2Z1 = M(Y2 * Z1);
        return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    };
    Point.prototype.is0 = function () {
        return this.equals(I);
    };
    /** Flip point over y coordinate. */
    Point.prototype.negate = function () {
        return new Point(M(-this.X), this.Y, this.Z, M(-this.T));
    };
    /** Point doubling. Complete formula. Cost: `4M + 4S + 1*a + 6add + 1*2`. */
    Point.prototype.double = function () {
        var _b = this, X1 = _b.X, Y1 = _b.Y, Z1 = _b.Z;
        var a = _a;
        // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
        var A = M(X1 * X1);
        var B = M(Y1 * Y1);
        var C = M(2n * M(Z1 * Z1));
        var D = M(a * A);
        var x1y1 = X1 + Y1;
        var E = M(M(x1y1 * x1y1) - A - B);
        var G = D + B;
        var F = G - C;
        var H = D - B;
        var X3 = M(E * F);
        var Y3 = M(G * H);
        var T3 = M(E * H);
        var Z3 = M(F * G);
        return new Point(X3, Y3, Z3, T3);
    };
    /** Point addition. Complete formula. Cost: `8M + 1*k + 8add + 1*2`. */
    Point.prototype.add = function (other) {
        var _b = this, X1 = _b.X, Y1 = _b.Y, Z1 = _b.Z, T1 = _b.T;
        var _c = apoint(other), X2 = _c.X, Y2 = _c.Y, Z2 = _c.Z, T2 = _c.T; // doesn't check if other on-curve
        var a = _a;
        var d = _d;
        // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
        var A = M(X1 * X2);
        var B = M(Y1 * Y2);
        var C = M(T1 * d * T2);
        var D = M(Z1 * Z2);
        var E = M((X1 + Y1) * (X2 + Y2) - A - B);
        var F = M(D - C);
        var G = M(D + C);
        var H = M(B - a * A);
        var X3 = M(E * F);
        var Y3 = M(G * H);
        var T3 = M(E * H);
        var Z3 = M(F * G);
        return new Point(X3, Y3, Z3, T3);
    };
    Point.prototype.subtract = function (other) {
        return this.add(apoint(other).negate());
    };
    /**
     * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
     * Uses {@link wNAF} for base point.
     * Uses fake point to mitigate side-channel leakage.
     * @param n scalar by which point is multiplied
     * @param safe safe mode guards against timing attacks; unsafe mode is faster
     */
    Point.prototype.multiply = function (n, safe) {
        if (safe === void 0) { safe = true; }
        if (!safe && (n === 0n || this.is0()))
            return I;
        assertRange(n, 1n, N);
        if (n === 1n)
            return this;
        if (this.equals(G))
            return wNAF(n).p;
        // init result point & fake point
        var p = I;
        var f = G;
        for (var d = this; n > 0n; d = d.double(), n >>= 1n) {
            // if bit is present, add to point
            // if not present, add to fake, for timing safety
            if (n & 1n)
                p = p.add(d);
            else if (safe)
                f = f.add(d);
        }
        return p;
    };
    Point.prototype.multiplyUnsafe = function (scalar) {
        return this.multiply(scalar, false);
    };
    /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
    Point.prototype.toAffine = function () {
        var _b = this, X = _b.X, Y = _b.Y, Z = _b.Z;
        // fast-paths for ZERO point OR Z=1
        if (this.equals(I))
            return { x: 0n, y: 1n };
        var iz = invert(Z, P);
        // (Z * Z^-1) must be 1, otherwise bad math
        if (M(Z * iz) !== 1n)
            err('invalid inverse');
        // x = X*Z^-1; y = Y*Z^-1
        var x = M(X * iz);
        var y = M(Y * iz);
        return { x: x, y: y };
    };
    Point.prototype.toBytes = function () {
        var _b = this.assertValidity().toAffine(), x = _b.x, y = _b.y;
        var b = numTo32bLE(y);
        // store sign in first LE byte
        b[31] |= x & 1n ? 0x80 : 0;
        return b;
    };
    Point.prototype.toHex = function () {
        return bytesToHex(this.toBytes());
    };
    Point.prototype.clearCofactor = function () {
        return this.multiply(big(h), false);
    };
    Point.prototype.isSmallOrder = function () {
        return this.clearCofactor().is0();
    };
    Point.prototype.isTorsionFree = function () {
        // Multiply by big number N. We can't `mul(N)` because of checks. Instead, we `mul(N/2)*2+1`
        var p = this.multiply(N / 2n, false).double();
        if (N % 2n)
            p = p.add(this);
        return p.is0();
    };
    return Point;
}());
exports.Point = Point;
/** Generator / base point */
var G = new Point(Gx, Gy, 1n, M(Gx * Gy));
/** Identity / zero point */
var I = new Point(0n, 1n, 1n, 0n);
// Static aliases
Point.BASE = G;
Point.ZERO = I;
var numTo32bLE = function (num) { return hexToBytes(padh(assertRange(num, 0n, B256), L2)).reverse(); };
var bytesToNumLE = function (b) { return big('0x' + bytesToHex(u8fr(abytes(b)).reverse())); };
var pow2 = function (x, power) {
    // pow2(x, 4) == x^(2^4)
    var r = x;
    while (power-- > 0n) {
        r *= r;
        r %= P;
    }
    return r;
};
// prettier-ignore
var pow_2_252_3 = function (x) {
    var x2 = (x * x) % P; // x^2,       bits 1
    var b2 = (x2 * x) % P; // x^3,       bits 11
    var b4 = (pow2(b2, 2n) * b2) % P; // x^(2^4-1), bits 1111
    var b5 = (pow2(b4, 1n) * x) % P; // x^(2^5-1), bits 11111
    var b10 = (pow2(b5, 5n) * b5) % P; // x^(2^10)
    var b20 = (pow2(b10, 10n) * b10) % P; // x^(2^20)
    var b40 = (pow2(b20, 20n) * b20) % P; // x^(2^40)
    var b80 = (pow2(b40, 40n) * b40) % P; // x^(2^80)
    var b160 = (pow2(b80, 80n) * b80) % P; // x^(2^160)
    var b240 = (pow2(b160, 80n) * b80) % P; // x^(2^240)
    var b250 = (pow2(b240, 10n) * b10) % P; // x^(2^250)
    var pow_p_5_8 = (pow2(b250, 2n) * x) % P; // < To pow to (p+3)/8, multiply it by x.
    return { pow_p_5_8: pow_p_5_8, b2: b2 };
};
var RM1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0n; // √-1
// for sqrt comp
// prettier-ignore
var uvRatio = function (u, v) {
    var v3 = M(v * v * v); // v³
    var v7 = M(v3 * v3 * v); // v⁷
    var pow = pow_2_252_3(u * v7).pow_p_5_8; // (uv⁷)^(p-5)/8
    var x = M(u * v3 * pow); // (uv³)(uv⁷)^(p-5)/8
    var vx2 = M(v * x * x); // vx²
    var root1 = x; // First root candidate
    var root2 = M(x * RM1); // Second root candidate; RM1 is √-1
    var useRoot1 = vx2 === u; // If vx² = u (mod p), x is a square root
    var useRoot2 = vx2 === M(-u); // If vx² = -u, set x <-- x * 2^((p-1)/4)
    var noRoot = vx2 === M(-u * RM1); // There is no valid root, vx² = -u√-1
    if (useRoot1)
        x = root1;
    if (useRoot2 || noRoot)
        x = root2; // We return root2 anyway, for const-time
    if ((M(x) & 1n) === 1n)
        x = M(-x); // edIsNegative
    return { isValid: useRoot1 || useRoot2, value: x };
};
// N == L, just weird naming
var modL_LE = function (hash) { return modN(bytesToNumLE(hash)); }; // modulo L; but little-endian
/** hashes.sha512 should conform to the interface. */
// TODO: rename
var sha512a = function () {
    var m = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        m[_i] = arguments[_i];
    }
    return hashes.sha512Async(concatBytes.apply(void 0, m));
}; // Async SHA512
var sha512s = function () {
    var m = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        m[_i] = arguments[_i];
    }
    return callHash('sha512')(concatBytes.apply(void 0, m));
};
// RFC8032 5.1.5
var hash2extK = function (hashed) {
    // slice creates a copy, unlike subarray
    var head = hashed.slice(0, L);
    head[0] &= 248; // Clamp bits: 0b1111_1000
    head[31] &= 127; // 0b0111_1111
    head[31] |= 64; // 0b0100_0000
    var prefix = hashed.slice(L, L2); // secret key "prefix"
    var scalar = modL_LE(head); // modular division over curve order
    var point = G.multiply(scalar); // public key point
    var pointBytes = point.toBytes(); // point serialized to Uint8Array
    return { head: head, prefix: prefix, scalar: scalar, point: point, pointBytes: pointBytes };
};
// RFC8032 5.1.5; getPublicKey async, sync. Hash priv key and extract point.
var getExtendedPublicKeyAsync = function (secretKey) {
    return sha512a(abytes(secretKey, L)).then(hash2extK);
};
var getExtendedPublicKey = function (secretKey) { return hash2extK(sha512s(abytes(secretKey, L))); };
/** Creates 32-byte ed25519 public key from 32-byte secret key. Async. */
var getPublicKeyAsync = function (secretKey) {
    return getExtendedPublicKeyAsync(secretKey).then(function (p) { return p.pointBytes; });
};
exports.getPublicKeyAsync = getPublicKeyAsync;
/** Creates 32-byte ed25519 public key from 32-byte secret key. To use, set `hashes.sha512` first. */
var getPublicKey = function (priv) { return getExtendedPublicKey(priv).pointBytes; };
exports.getPublicKey = getPublicKey;
var hashFinishA = function (res) { return sha512a(res.hashable).then(res.finish); };
var hashFinishS = function (res) { return res.finish(sha512s(res.hashable)); };
// Code, shared between sync & async sign
var _sign = function (e, rBytes, msg) {
    var P = e.pointBytes, s = e.scalar;
    var r = modL_LE(rBytes); // r was created outside, reduce it modulo L
    var R = G.multiply(r).toBytes(); // R = [r]B
    var hashable = concatBytes(R, P, msg); // dom2(F, C) || R || A || PH(M)
    var finish = function (hashed) {
        // k = SHA512(dom2(F, C) || R || A || PH(M))
        var S = modN(r + modL_LE(hashed) * s); // S = (r + k * s) mod L; 0 <= s < l
        return abytes(concatBytes(R, numTo32bLE(S)), L2); // 64-byte sig: 32b R.x + 32b LE(S)
    };
    return { hashable: hashable, finish: finish };
};
/**
 * Signs message using secret key. Async.
 * Follows RFC8032 5.1.6.
 */
var signAsync = function (message, secretKey) { return __awaiter(void 0, void 0, void 0, function () {
    var m, e, rBytes;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                m = abytes(message);
                return [4 /*yield*/, getExtendedPublicKeyAsync(secretKey)];
            case 1:
                e = _b.sent();
                return [4 /*yield*/, sha512a(e.prefix, m)];
            case 2:
                rBytes = _b.sent();
                return [2 /*return*/, hashFinishA(_sign(e, rBytes, m))]; // gen R, k, S, then 64-byte signature
        }
    });
}); };
exports.signAsync = signAsync;
/**
 * Signs message using secret key. To use, set `hashes.sha512` first.
 * Follows RFC8032 5.1.6.
 */
var sign = function (message, secretKey) {
    var m = abytes(message);
    var e = getExtendedPublicKey(secretKey);
    var rBytes = sha512s(e.prefix, m); // r = SHA512(dom2(F, C) || prefix || PH(M))
    return hashFinishS(_sign(e, rBytes, m)); // gen R, k, S, then 64-byte signature
};
exports.sign = sign;
var defaultVerifyOpts = { zip215: true };
var _verify = function (sig, msg, pub, opts) {
    if (opts === void 0) { opts = defaultVerifyOpts; }
    sig = abytes(sig, L2); // Signature hex str/Bytes, must be 64 bytes
    msg = abytes(msg); // Message hex str/Bytes
    pub = abytes(pub, L);
    var zip215 = opts.zip215; // switch between zip215 and rfc8032 verif
    var A;
    var R;
    var s;
    var SB;
    var hashable = Uint8Array.of();
    try {
        A = Point.fromBytes(pub, zip215); // public key A decoded
        R = Point.fromBytes(sig.slice(0, L), zip215); // 0 <= R < 2^256: ZIP215 R can be >= P
        s = bytesToNumLE(sig.slice(L, L2)); // Decode second half as an integer S
        SB = G.multiply(s, false); // in the range 0 <= s < L
        hashable = concatBytes(R.toBytes(), A.toBytes(), msg); // dom2(F, C) || R || A || PH(M)
    }
    catch (error) { }
    var finish = function (hashed) {
        // k = SHA512(dom2(F, C) || R || A || PH(M))
        if (SB == null)
            return false; // false if try-catch catched an error
        if (!zip215 && A.isSmallOrder())
            return false; // false for SBS: Strongly Binding Signature
        var k = modL_LE(hashed); // decode in little-endian, modulo L
        var RkA = R.add(A.multiply(k, false)); // [8]R + [8][k]A'
        return RkA.add(SB.negate()).clearCofactor().is0(); // [8][S]B = [8]R + [8][k]A'
    };
    return { hashable: hashable, finish: finish };
};
/** Verifies signature on message and public key. Async. Follows RFC8032 5.1.7. */
var verifyAsync = function (signature_1, message_1, publicKey_1) {
    var args_1 = [];
    for (var _i = 3; _i < arguments.length; _i++) {
        args_1[_i - 3] = arguments[_i];
    }
    return __awaiter(void 0, __spreadArray([signature_1, message_1, publicKey_1], args_1, true), void 0, function (signature, message, publicKey, opts) {
        if (opts === void 0) { opts = defaultVerifyOpts; }
        return __generator(this, function (_b) {
            return [2 /*return*/, hashFinishA(_verify(signature, message, publicKey, opts))];
        });
    });
};
exports.verifyAsync = verifyAsync;
/** Verifies signature on message and public key. To use, set `hashes.sha512` first. Follows RFC8032 5.1.7. */
var verify = function (signature, message, publicKey, opts) {
    if (opts === void 0) { opts = defaultVerifyOpts; }
    return hashFinishS(_verify(signature, message, publicKey, opts));
};
exports.verify = verify;
/** Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves. */
var etc = {
    bytesToHex: bytesToHex,
    hexToBytes: hexToBytes,
    concatBytes: concatBytes,
    mod: M,
    invert: invert,
    randomBytes: randomBytes,
};
exports.etc = etc;
var hashes = {
    sha512Async: function (message) { return __awaiter(void 0, void 0, void 0, function () {
        var s, m, _b;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    s = subtle();
                    m = concatBytes(message);
                    _b = u8n;
                    return [4 /*yield*/, s.digest('SHA-512', m.buffer)];
                case 1: return [2 /*return*/, _b.apply(void 0, [_c.sent()])];
            }
        });
    }); },
    sha512: undefined,
};
exports.hashes = hashes;
// FIPS 186 B.4.1 compliant key generation produces private keys
// with modulo bias being neglible. takes >N+16 bytes, returns (hash mod n-1)+1
var randomSecretKey = function (seed) {
    if (seed === void 0) { seed = randomBytes(L); }
    return seed;
};
var keygen = function (seed) {
    var secretKey = randomSecretKey(seed);
    var publicKey = getPublicKey(secretKey);
    return { secretKey: secretKey, publicKey: publicKey };
};
exports.keygen = keygen;
var keygenAsync = function (seed) { return __awaiter(void 0, void 0, void 0, function () {
    var secretKey, publicKey;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                secretKey = randomSecretKey(seed);
                return [4 /*yield*/, getPublicKeyAsync(secretKey)];
            case 1:
                publicKey = _b.sent();
                return [2 /*return*/, { secretKey: secretKey, publicKey: publicKey }];
        }
    });
}); };
exports.keygenAsync = keygenAsync;
/** ed25519-specific key utilities. */
var utils = {
    getExtendedPublicKeyAsync: getExtendedPublicKeyAsync,
    getExtendedPublicKey: getExtendedPublicKey,
    randomSecretKey: randomSecretKey,
};
exports.utils = utils;
// ## Precomputes
// --------------
var W = 8; // W is window size
var scalarBits = 256;
var pwindows = Math.ceil(scalarBits / W) + 1; // 33 for W=8, NOT 32 - see wNAF loop
var pwindowSize = Math.pow(2, (W - 1)); // 128 for W=8
var precompute = function () {
    var points = [];
    var p = G;
    var b = p;
    for (var w = 0; w < pwindows; w++) {
        b = p;
        points.push(b);
        for (var i = 1; i < pwindowSize; i++) {
            b = b.add(p);
            points.push(b);
        } // i=1, bc we skip 0
        p = b.double();
    }
    return points;
};
var Gpows = undefined; // precomputes for base point G
// const-time negate
var ctneg = function (cnd, p) {
    var n = p.negate();
    return cnd ? n : p;
};
/**
 * Precomputes give 12x faster getPublicKey(), 10x sign(), 2x verify() by
 * caching multiples of G (base point). Cache is stored in 32MB of RAM.
 * Any time `G.multiply` is done, precomputes are used.
 * Not used for getSharedSecret, which instead multiplies random pubkey `P.multiply`.
 *
 * w-ary non-adjacent form (wNAF) precomputation method is 10% slower than windowed method,
 * but takes 2x less RAM. RAM reduction is possible by utilizing `.subtract`.
 *
 * !! Precomputes can be disabled by commenting-out call of the wNAF() inside Point#multiply().
 */
var wNAF = function (n) {
    var comp = Gpows || (Gpows = precompute());
    var p = I;
    var f = G; // f must be G, or could become I in the end
    var pow_2_w = Math.pow(2, W); // 256 for W=8
    var maxNum = pow_2_w; // 256 for W=8
    var mask = big(pow_2_w - 1); // 255 for W=8 == mask 0b11111111
    var shiftBy = big(W); // 8 for W=8
    for (var w = 0; w < pwindows; w++) {
        var wbits = Number(n & mask); // extract W bits.
        n >>= shiftBy; // shift number by W bits.
        // We use negative indexes to reduce size of precomputed table by 2x.
        // Instead of needing precomputes 0..256, we only calculate them for 0..128.
        // If an index > 128 is found, we do (256-index) - where 256 is next window.
        // Naive: index +127 => 127, +224 => 224
        // Optimized: index +127 => 127, +224 => 256-32
        if (wbits > pwindowSize) {
            wbits -= maxNum;
            n += 1n;
        }
        var off = w * pwindowSize;
        var offF = off; // offsets, evaluate both
        var offP = off + Math.abs(wbits) - 1;
        var isEven = w % 2 !== 0; // conditions, evaluate both
        var isNeg = wbits < 0;
        if (wbits === 0) {
            // off == I: can't add it. Adding random offF instead.
            f = f.add(ctneg(isEven, comp[offF])); // bits are 0: add garbage to fake point
        }
        else {
            p = p.add(ctneg(isNeg, comp[offP])); // bits are 1: add to result point
        }
    }
    if (n !== 0n)
        err('invalid wnaf');
    return { p: p, f: f }; // return both real and fake points for JIT
};

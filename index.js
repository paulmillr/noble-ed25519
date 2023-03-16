const B256 = 2n ** 256n;
const P = 2n ** 255n - 19n;
const N = 2n ** 252n + 27742317777372353535851937790883648493n;
export const CURVE = {
    a: -1n,
    d: 37095705934669439343138083508754565189542113879843219016388785533085940283555n,
    P, l: N, n: N,
    h: 8,
    Gx: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
    Gy: 46316835694926478169428394003475163141307993866256225615783033603165251855960n
};
const err = (m = '') => { throw new Error(m); };
const str = (s) => typeof s === 'string';
const au8 = (a, l) => !(a instanceof Uint8Array) || (typeof l === 'number' && l > 0 && a.length !== l) ?
    err('Uint8Array expected') : a;
const u8n = (data) => new Uint8Array(data);
const u8fr = (arr) => Uint8Array.from(arr);
const toU8 = (a, len) => au8(str(a) ? h2b(a) : u8fr(a), len);
const mod = (a, b = P) => { let r = a % b; return r >= 0n ? r : b + r; };
const isPoint = (p) => (p instanceof Point ? p : err('Point expected'));
let Gpows = undefined;
class Point {
    constructor(ex, ey, ez, et) {
        this.ex = ex;
        this.ey = ey;
        this.ez = ez;
        this.et = et;
    }
    static fromAffine(p) {
        return new Point(p.x, p.y, 1n, mod(p.x * p.y));
    }
    get x() { return this.aff().x; }
    get y() { return this.aff().y; }
    eql(other) {
        const { ex: X1, ey: Y1, ez: Z1 } = this;
        const { ex: X2, ey: Y2, ez: Z2 } = isPoint(other);
        const X1Z2 = mod(X1 * Z2), X2Z1 = mod(X2 * Z1);
        const Y1Z2 = mod(Y1 * Z2), Y2Z1 = mod(Y2 * Z1);
        return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }
    neg() {
        return new Point(mod(-this.ex), this.ey, this.ez, mod(-this.et));
    }
    dbl() {
        const { ex: X1, ey: Y1, ez: Z1 } = this;
        const { a } = CURVE;
        const A = mod(X1 * X1);
        const B = mod(Y1 * Y1);
        const C = mod(2n * mod(Z1 * Z1));
        const D = mod(a * A);
        const x1y1 = X1 + Y1;
        const E = mod(mod(x1y1 * x1y1) - A - B);
        const G = D + B;
        const F = G - C;
        const H = D - B;
        const X3 = mod(E * F);
        const Y3 = mod(G * H);
        const T3 = mod(E * H);
        const Z3 = mod(F * G);
        return new Point(X3, Y3, Z3, T3);
    }
    add(other) {
        const { ex: X1, ey: Y1, ez: Z1, et: T1 } = this;
        const { ex: X2, ey: Y2, ez: Z2, et: T2 } = isPoint(other);
        const { a, d } = CURVE;
        const A = mod(X1 * X2);
        const B = mod(Y1 * Y2);
        const C = mod(T1 * d * T2);
        const D = mod(Z1 * Z2);
        const E = mod((X1 + Y1) * (X2 + Y2) - A - B);
        const F = mod(D - C);
        const G = mod(D + C);
        const H = mod(B - a * A);
        const X3 = mod(E * F);
        const Y3 = mod(G * H);
        const T3 = mod(E * H);
        const Z3 = mod(F * G);
        return new Point(X3, Y3, Z3, T3);
    }
    sub(p) { return this.add(p.neg()); }
    mul(n, safe = true) {
        if (n === 0n)
            return safe === true ? err('cannot multiply by 0') : I;
        if (!(typeof n === 'bigint' && 0n < n && n < N))
            err('invalid scalar, must be < L');
        if (!safe && this.eql(I) || n === 1n)
            return this;
        if (this.eql(G))
            return wNAF(n).p;
        let p = I, f = G;
        for (let d = this; n > 0n; d = d.dbl(), n >>= 1n) {
            if (n & 1n)
                p = p.add(d);
            else if (safe)
                f = f.add(d);
        }
        return p;
    }
    multiply(scalar) { return this.mul(scalar); }
    clearCofactor() { return this.mul(BigInt(CURVE.h), false); }
    isSmallOrder() { return this.clearCofactor().eql(I); }
    isTorsionFree() {
        let p = this.mul(N / 2n, false).dbl();
        if (N % 2n)
            p = p.add(this);
        return p.eql(I);
    }
    aff() {
        const { ex: x, ey: y, ez: z } = this;
        if (this.eql(I))
            return { x: 0n, y: 0n };
        const iz = inv(z);
        if (mod(z * iz) !== 1n)
            err('invalid inverse');
        return { x: mod(x * iz), y: mod(y * iz) };
    }
    static fromHex(hex, strict = true) {
        const { d } = CURVE;
        hex = toU8(hex, 32);
        const normed = hex.slice();
        normed[31] = hex[31] & ~0x80;
        const y = b2n_LE(normed);
        if (y === 0n) {
        }
        else {
            if (strict && !(0n < y && y < P))
                err('bad y coordinate 1');
            if (!strict && !(0n < y && y < B256))
                err('bad y coordinate 2');
        }
        const y2 = mod(y * y);
        const u = mod(y2 - 1n);
        const v = mod(d * y2 + 1n);
        let { isValid, value: x } = uvRatio(u, v);
        if (!isValid)
            err('bad y coordinate 3');
        const isXOdd = (x & 1n) === 1n;
        const isHeadOdd = (hex[31] & 0x80) !== 0;
        if (isHeadOdd !== isXOdd)
            x = mod(-x);
        return new Point(x, y, 1n, mod(x * y));
    }
    toRawBytes() {
        const { x, y } = this.aff();
        const b = n2b_32LE(y);
        b[31] |= x & 1n ? 0x80 : 0;
        return b;
    }
    toHex() { return b2h(this.toRawBytes()); }
}
Point.BASE = new Point(CURVE.Gx, CURVE.Gy, 1n, mod(CURVE.Gx * CURVE.Gy));
Point.ZERO = new Point(0n, 1n, 1n, 0n);
const { BASE: G, ZERO: I } = Point;
export const ExtendedPoint = Point;
const concatB = (...arrs) => {
    const r = u8n(arrs.reduce((sum, a) => sum + a.length, 0));
    let pad = 0;
    arrs.forEach(a => { r.set(au8(a), pad); pad += a.length; });
    return r;
};
const padh = (num, pad) => num.toString(16).padStart(pad, '0');
const b2h = (b) => Array.from(b).map(e => padh(e, 2)).join('');
const h2b = (hex) => {
    const l = hex.length;
    if (!str(hex) || l % 2)
        err('hex invalid');
    const arr = u8n(l / 2);
    for (let i = 0; i < arr.length; i++) {
        const j = i * 2;
        const h = hex.slice(j, j + 2);
        const b = Number.parseInt(h, 16);
        if (Number.isNaN(b) || b < 0)
            err('hex invalid b');
        arr[i] = b;
    }
    return arr;
};
const n2b_32BE = (num) => h2b(num.toString(16).padStart(32 * 2, '0'));
const n2b_32LE = (num) => n2b_32BE(num).reverse();
const b2n_LE = (b) => BigInt('0x' + b2h(u8fr(au8(b)).reverse()));
const inv = (num, md = P) => {
    if (num === 0n || md <= 0n)
        err(`no invert n=${num} mod=${md}`);
    let a = mod(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
    while (a !== 0n) {
        const q = b / a, r = b % a;
        const m = x - u * q, n = y - v * q;
        b = a, a = r, x = u, y = v, u = m, v = n;
    }
    return b === 1n ? mod(x, md) : err('no invert');
};
const pow2 = (x, power) => {
    let r = x;
    while (power-- > 0n) {
        r *= r;
        r %= P;
    }
    return r;
};
const pow_2_252_3 = (x) => {
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
    return { pow_p_5_8, b2 };
};
const RM1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
const uvRatio = (u, v) => {
    const v3 = mod(v * v * v);
    const v7 = mod(v3 * v3 * v);
    const pow = pow_2_252_3(u * v7).pow_p_5_8;
    let x = mod(u * v3 * pow);
    const vx2 = mod(v * x * x);
    const root1 = x;
    const root2 = mod(x * RM1);
    const useRoot1 = vx2 === u;
    const useRoot2 = vx2 === mod(-u);
    const noRoot = vx2 === mod(-u * RM1);
    if (useRoot1)
        x = root1;
    if (useRoot2 || noRoot)
        x = root2;
    if ((mod(x) & 1n) === 1n)
        x = mod(-x);
    return { isValid: useRoot1 || useRoot2, value: x };
};
const modL_LE = (hash) => mod(b2n_LE(hash), N);
let _shaS;
const sha512a = (...m) => etc.sha512Async(...m);
const sha512s = (...m) => typeof _shaS === 'function' ? _shaS(...m) : err('etc.sha512Sync not set');
const adj25519 = (bytes) => {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
};
const hash2extK = (hashed) => {
    const head = hashed.slice(0, 32);
    adj25519(head);
    const prefix = hashed.slice(32, 64);
    const scalar = modL_LE(head);
    const point = G.mul(scalar);
    const pointBytes = point.toRawBytes();
    return { head, prefix, scalar, point, pointBytes };
};
const getExtendedPublicKeyAsync = async (priv) => hash2extK(await sha512a(toU8(priv, 32)));
const getExtendedPublicKey = (priv) => hash2extK(sha512s(toU8(priv, 32)));
export const getPublicKeyAsync = async (priv) => (await getExtendedPublicKeyAsync(priv)).pointBytes;
export const getPublicKey = (priv) => getExtendedPublicKey(priv).pointBytes;
const hashFinishA = async (res) => res.finish(await sha512a(res.hashable));
const hashFinishS = (res) => res.finish(sha512s(res.hashable));
const _sign = (s, P, rBytes, msg) => {
    const r = modL_LE(rBytes);
    const R = G.mul(r).toRawBytes();
    const hashable = concatB(R, P, msg);
    const finish = (hashed) => {
        const S = mod(r + modL_LE(hashed) * s, N);
        return au8(concatB(R, n2b_32LE(S)), 64);
    };
    return { hashable, finish };
};
export const signAsync = async (msg, privKey) => {
    const m = toU8(msg);
    const { prefix, scalar: s, pointBytes: P } = await getExtendedPublicKeyAsync(privKey);
    const rBytes = await sha512a(prefix, m);
    return await hashFinishA(_sign(s, P, rBytes, m));
};
export const sign = (msg, privKey) => {
    const m = toU8(msg);
    const { prefix, scalar: s, pointBytes: P } = getExtendedPublicKey(privKey);
    const rBytes = sha512s(prefix, m);
    return hashFinishS(_sign(s, P, rBytes, m));
};
const _verify = (sig, msg, pub) => {
    msg = toU8(msg);
    sig = toU8(sig, 64);
    const A = pub instanceof Point ? pub : Point.fromHex(pub, false);
    const R = Point.fromHex(sig.slice(0, 32), false);
    const s = b2n_LE(sig.slice(32, 64));
    const SB = G.mul(s, false);
    const hashable = concatB(R.toRawBytes(), A.toRawBytes(), msg);
    const finish = (hashed) => {
        const k = modL_LE(hashed);
        const RkA = R.add(A.mul(k, false));
        return RkA.sub(SB).clearCofactor().eql(I);
    };
    return { hashable, finish };
};
export const verifyAsync = async (sig, msg, pubKey) => await hashFinishA(_verify(sig, msg, pubKey));
export const verify = (sig, msg, pubKey) => hashFinishS(_verify(sig, msg, pubKey));
const cr = () => typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;
export const etc = {
    bytesToHex: b2h, hexToBytes: h2b,
    concatBytes: concatB, mod, invert: inv,
    randomBytes: (len) => {
        const crypto = cr();
        if (!crypto)
            err('crypto.getRandomValues must be defined');
        return crypto.getRandomValues(u8n(len));
    },
    sha512Async: async (...messages) => {
        const crypto = cr();
        if (!crypto)
            err('crypto.subtle or etc.sha512Async must be defined');
        const m = concatB(...messages);
        return u8n(await crypto.subtle.digest('SHA-512', m.buffer));
    },
    sha512Sync: undefined,
};
Object.defineProperties(etc, { sha512Sync: {
        configurable: false, get() { return _shaS; }, set(f) { if (!_shaS)
            _shaS = f; },
    } });
export const utils = {
    getExtendedPublicKeyAsync, getExtendedPublicKey, precompute(p, w = 8) { return p; },
    randomPrivateKey: () => etc.randomBytes(32),
};
const W = 8;
const precompute = () => {
    const points = [];
    const windows = 256 / W + 1;
    let p = G, b = p;
    for (let w = 0; w < windows; w++) {
        b = p;
        points.push(b);
        for (let i = 1; i < 2 ** (W - 1); i++) {
            b = b.add(p);
            points.push(b);
        }
        p = b.dbl();
    }
    return points;
};
const wNAF = (n) => {
    const comp = Gpows || (Gpows = precompute());
    const neg = (cnd, p) => { let n = p.neg(); return cnd ? n : p; };
    let p = I, f = G;
    const windows = 1 + 256 / W;
    const wsize = 2 ** (W - 1);
    const mask = BigInt(2 ** W - 1);
    const maxNum = 2 ** W;
    const shiftBy = BigInt(W);
    for (let w = 0; w < windows; w++) {
        const off = w * wsize;
        let wbits = Number(n & mask);
        n >>= shiftBy;
        if (wbits > wsize) {
            wbits -= maxNum;
            n += 1n;
        }
        const off1 = off, off2 = off + Math.abs(wbits) - 1;
        const cnd1 = w % 2 !== 0, cnd2 = wbits < 0;
        if (wbits === 0) {
            f = f.add(neg(cnd1, comp[off1]));
        }
        else {
            p = p.add(neg(cnd2, comp[off2]));
        }
    }
    return { p, f };
};

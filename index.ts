/*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
/**
 * TODO:
 * - copy comments from prev version
 * - verify if add()/dbl() are rfc8032 algo
 * - Point#ok()
 */
const B256 = 2n ** 256n; // ed25519 is twisted edwards curve with formula −x² + y² = 1 + dx²y²
const P = 2n ** 255n - 19n;                                     // curve's prime field
const N = 2n ** 252n + 27742317777372353535851937790883648493n; // curve's (group) order
const _a = -1n; // curve's params: a = -1; d = -(121665/121666) == -(121665*inv(121666)) mod P
const _d = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const h = 8;                                                    // cofactor
const Gx = 15112221349535400772501151409588531511454012693041857206046113283949847762202n; // gen X
const Gy = 46316835694926478169428394003475163141307993866256225615783033603165251855960n; // gen Y
const CURVE = { a: _a, d: _d, P, l: N, n: N, h, Gx, Gy };
type Bytes = Uint8Array; type Hex = Bytes | string; type PubKey = Hex | Point;
const RM1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n; // √-1
const err = (m = ''): never => { throw new Error(m); };
const big = (n: any): n is bigint => typeof n === 'bigint'; // is big integer
const str = (s: any): s is string => typeof s === 'string'; // is string
const ge = (n: bigint) => big(n) && 0n < n && n < N;    // is group element
const u8 = (a: any, l?: number): Bytes =>               // is Uint8Array (of specific length)
  !(a instanceof Uint8Array) || (typeof l === 'number' && l > 0 && a.length !== l) ?
  err('Uint8Array expected') : a;
const u8n = (data?: any) => new Uint8Array(data);       // creates Uint8Array
const u8fr = (arr: any) => Uint8Array.from(arr);        // another shortcut
const toU8 = (a: any, len?: number) => u8(str(a) ? h2b(a) : u8fr(a), len);  // normalize (hex/u8a) to u8a
const isPoint = (p: any) => (p instanceof Point ? p : err('Point expected')); // is 3d point
const mod = (a: bigint, b = P) => { let r = a % b; return r >= 0n ? r : b + r; }; // mod division
let Gpows: Point[] | undefined = undefined;             // precomputes for base point G
interface AffinePoint { x: bigint, y: bigint }          // Point in 2d xy affine coords
class Point {                                           // Point in xyzt extended coords
  constructor(readonly ex: bigint, readonly ey: bigint, readonly ez: bigint, readonly et: bigint) {}
  static BASE = new Point(Gx, Gy, 1n, mod(Gx * Gy));    // Generator / base point
  static ZERO = new Point(0n, 1n, 1n, 0n);              // Identity / zero point
  get x() { return this.aff().x; }
  get y() { return this.aff().y; }
  eql(other: Point): boolean {                          // equality check: compare points
    isPoint(other);
    const { ex: X1, ey: Y1, ez: Z1 } = this;
    const { ex: X2, ey: Y2, ez: Z2 } = other;
    const X1Z2 = mod(X1 * Z2), X2Z1 = mod(X2 * Z1);
    const Y1Z2 = mod(Y1 * Z2), Y2Z1 = mod(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }
  neg(): Point {                                        // negate: flip over the affine x coordinate
    return new Point(mod(-this.ex), this.ey, this.ez, mod(-this.et));
  }
  dbl(): Point { // Fast algo for doubling Extended Point
    const { ex: X1, ey: Y1, ez: Z1 } = this; // Cost: 4M + 4S + 1*a + 6add + 1*2.
    const { a } = CURVE; // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
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
  add(other: Point) { // Fast algo for adding 2 Extended Points when curve's a=-1.
    isPoint(other);   // Note: It does not check whether the `other` point is valid.
    const { ex: X1, ey: Y1, ez: Z1, et: T1 } = this; // http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-4
    const { ex: X2, ey: Y2, ez: Z2, et: T2 } = other; // Cost: 8M + 8add + 2*2.
    const A = mod((Y1 - X1) * (Y2 + X2));
    const B = mod((Y1 + X1) * (Y2 - X2));
    const F = mod(B - A);
    if (F === 0n) return this.dbl(); // Same point.
    const C = mod(Z1 * 2n * T2);
    const D = mod(T1 * 2n * Z2);
    const E = D + C;
    const G = B + A;
    const H = D - C;
    const X3 = mod(E * F);
    const Y3 = mod(G * H);
    const T3 = mod(E * H);
    const Z3 = mod(F * G);
    return new Point(X3, Y3, Z3, T3);
  }
  sub(other: Point): Point { return this.add(other.neg()); }
  mul(scalar: bigint, safe = true): Point {
    let n = scalar;
    if (n === 0n) return safe === true ? err('cannot multiply by 0') : I;
    if (!ge(n)) err('invalid scalar, must be < L');
    if (!safe && this.eql(I) || n === 1n) return this;
    if (this.eql(G)) return wNAF(n).p;
    let p = I, f = G;                                   // init result point & fake point
    for (let d: Point = this; n > 0n; d = d.dbl(), n >>= 1n) { // double-and-add ladder
      if (n & 1n) p = p.add(d);                         // if bit is present, add to point
      else if (safe) f = f.add(d);                      // if not, add to fake for timing safety
    }
    return p;
  }
  multiply(scalar: bigint) { return this.mul(scalar); }
  clearCofactor(): Point { return this.mul(BigInt(h), false); }
  isSmallOrder(): boolean { return this.clearCofactor().eql(I); }
  isTorsionFree(): boolean {
    let p = this.mul(N / 2n, false).dbl();
    if (N % 2n) p = p.add(this); // P^(N+1)
    return p.eql(I);
  }
  aff(): AffinePoint {                                  // converts point to 2d xy affine point
    const { ex: x, ey: y, ez: z } = this;                           // (x, y, z, t) ∋ (x=x/z, y=y/z, t=xy)
    if (this.eql(I)) return { x: 0n, y: 0n };
    const iz = inv(z);
    if (mod(z * iz) !== 1n) err('invalid inverse');
    return { x: mod(x * iz), y: mod(y * iz) }
  }
  static fromHex(hex: Hex, strict = true) { // RFC8032 5.1.3: convert hex / Uint8Array to Point.
    const { d } = CURVE;
    hex = toU8(hex, 32);
    const normed = hex.slice();                         // copy the array to not mess it up
    normed[31] = hex[31] & ~0x80;
    const y = b2n_LE(normed);
    if (y === 0n) {
    } else {
      if (strict && !(0n < y && y < P)) err('bad y coordinate 1'); // strict=true [1..P-1]
      if (!strict && !(0n < y && y < B256)) err('bad y coordinate 2'); // strict=false [1..2^256-1]
    }
    const y2 = mod(y * y);
    const u = mod(y2 - 1n);
    const v = mod(d * y2 + 1n);
    let { isValid, value: x } = uvRatio(u, v);
    if (!isValid) err('bad y coordinate 3');
    const isXOdd = (x & 1n) === 1n;
    const isHeadOdd = (hex[31] & 0x80) !== 0;
    if (isHeadOdd !== isXOdd) x = mod(-x);
    return new Point(x, y, 1n, mod(x * y));
  }
  toRawBytes(): Bytes {
    const { x, y } = this.aff();
    const b = n2b_32LE(y);
    b[31] |= this.x & 1n ? 0x80 : 0;
    return b;
  }
  toHex(): string {
    return b2h(this.toRawBytes());
  }
}
const { BASE: G, ZERO: I } = Point;                                 // Generator, identity points
const concatB = (...arrs: Bytes[]) => {                 // concatenate Uint8Array-s
  const r = u8n(arrs.reduce((sum, a) => sum + a.length, 0)); // create u8a of summed length
  let pad = 0;                                               // walk through each array, ensure
  arrs.forEach(a => { r.set(u8(a), pad); pad += a.length }); // they have proper type
  return r;
};
const padh = (num: number | bigint, pad: number) => num.toString(16).padStart(pad, '0')
const b2h = (b: Bytes): string => Array.from(b).map(e => padh(e, 2)).join(''); // bytes to hex
const h2b = (hex: string): Bytes => {                   // hex to bytes
  const l = hex.length;                                 // error if not string,
  if (!str(hex) || l % 2) err('hex invalid');           // or has odd length like 3, 5.
  const arr = u8n(l / 2);                               // create result array
  for (let i = 0; i < arr.length; i++) {
    const j = i * 2;
    const h = hex.slice(j, j + 2);                      // hexByte. slice is faster than substr
    const b = Number.parseInt(h, 16);                   // byte, created from string part
    if (Number.isNaN(b) || b < 0) err('hex invalid b'); // byte must be valid 0 <= byte < 256
    arr[i] = b;
  }
  return arr;
};
const n2b_32BE = (num: bigint) => h2b(num.toString(16).padStart(32 * 2, '0')); // number to bytes BE
const n2b_32LE = (num: bigint) => n2b_32BE(num).reverse();                     // number to bytes LE
const b2n_LE = (b: Bytes): bigint => BigInt('0x' + b2h(u8fr(u8(b)).reverse())) // bytes LE to number
const inv = (num: bigint, md = P): bigint => {          // modular inversion
  if (num === 0n || md <= 0n) err(`no invert n=${num} mod=${md}`); // no negative exponents
  let a = mod(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {                                    // uses euclidean gcd algorithm
    const q = b / a, r = b % a;                         // not constant-time
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === 1n ? mod(x, md) : err('no invert');      // b is gcd at this point
};
const pow2 = (x: bigint, power: bigint): bigint => {
  let r = x;
  while (power-- > 0n) { r *= r; r %= P; }
  return r;
}
const pow_2_252_3 = (x: bigint) => {
  const x2 = (x * x) % P;                               // x^2,       bits 1
  const b2 = (x2 * x) % P;                              // x^3,       bits 11
  const b4 = (pow2(b2, 2n) * b2) % P;                   // x^(2^4-1), bits 1111
  const b5 = (pow2(b4, 1n) * x) % P;                    // x^(2^5-1), bits 11111
  const b10 = (pow2(b5, 5n) * b5) % P;                  // x^(2^10)
  const b20 = (pow2(b10, 10n) * b10) % P;               // x^(2^20)
  const b40 = (pow2(b20, 20n) * b20) % P;               // x^(2^40)
  const b80 = (pow2(b40, 40n) * b40) % P;               // x^(2^80)
  const b160 = (pow2(b80, 80n) * b80) % P;              // x^(2^160)
  const b240 = (pow2(b160, 80n) * b80) % P;             // x^(2^240)
  const b250 = (pow2(b240, 10n) * b10) % P;             // x^(2^250)
  const pow_p_5_8 = (pow2(b250, 2n) * x) % P; // < To pow to (p+3)/8, multiply it by x.
  return { pow_p_5_8, b2 };
}
const uvRatio = (u: bigint, v: bigint): { isValid: boolean, value: bigint } => {
  const v3 = mod(v * v * v);                            // v³
  const v7 = mod(v3 * v3 * v);                          // v⁷
  const pow = pow_2_252_3(u * v7).pow_p_5_8;            // (uv⁷)^(p-5)/8
  let x = mod(u * v3 * pow);                            // (uv³)(uv⁷)^(p-5)/8
  const vx2 = mod(v * x * x);                           // vx²
  const root1 = x;                                      // First root candidate
  const root2 = mod(x * RM1);                           // Second root candidate; RM1 is √-1
  const useRoot1 = vx2 === u;                           // If vx² = u (mod p), x is a square root
  const useRoot2 = vx2 === mod(-u);                     // If vx² = -u, set x <-- x * 2^((p-1)/4)
  const noRoot = vx2 === mod(-u * RM1);                 // There is no valid root, vx² = -u√-1
  if (useRoot1) x = root1;
  if (useRoot2 || noRoot) x = root2;                    // We return root2 anyway, for const-time
  if ((mod(x) & 1n) === 1n) x = mod(-x);                // edIsNegative
  return { isValid: useRoot1 || useRoot2, value: x };
}
const modL_LE = (hash: Bytes): bigint => mod(b2n_LE(hash), N); // Little-endian modulo n
type ExtK = { head: Bytes, prefix: Bytes, scalar: bigint, point: Point, pointBytes: Bytes };
const adj25519 = (bytes: Bytes) => {                    // curve25519 bit clamping
  bytes[0] &= 248;                                      // 0b1111_1000
  bytes[31] &= 127;                                     // 0b0111_1111
  bytes[31] |= 64;                                      // 0b0100_0000
}
const hash2extK = (hashed: Bytes): ExtK => {            // RFC8032 5.1.5
  const head = hashed.slice(0, 32);                     // slice creates a copy, unlike subarray
  adj25519(head);                                       // Clamp bits
  const prefix = hashed.slice(32, 64);                  // private key "prefix"
  const scalar = modL_LE(head);                         // modular division over curve order
  const point = G.mul(scalar);                          // public key point
  const pointBytes = point.toRawBytes();                // point serialized to Uint8Array
  return { head, prefix, scalar, point, pointBytes };
}
type Sha512FnSync = undefined | ((...messages: Bytes[]) => Bytes);
let _shaS: Sha512FnSync;
const sha512a = (...m: Bytes[]) => utils.sha512Async(...m);  // Async SHA512
const sha512s = (...m: Bytes[]) => // Sync SHA512, not set by default
  typeof _shaS === 'function' ? _shaS(...m) : err('utils.sha512Sync not set');
const extendedPubAsync = async (priv: Hex) => hash2extK(await sha512a(toU8(priv, 32)));
const extendedPubSync        = (priv: Hex) => hash2extK(sha512s(toU8(priv, 32))); // RFC8032 5.1.5
const pubAsync = async (priv: Hex): Promise<Bytes> => (await extendedPubAsync(priv)).pointBytes;
const pubSync        = (priv: Hex): Bytes => extendedPubSync(priv).pointBytes;
type Finishable<T> = {                                  // Helps to reduce logic duplication between
  hashable: Bytes, finish: (hashed: Bytes) => T         // sync & async versions of sign(), verify()
}                                                       // hashable=start(); finish(hash(hashable));
const hashFinishA = async <T>(res: Finishable<T>) => res.finish(await sha512a(res.hashable));
const hashFinishS = <T>(res: Finishable<T>) => res.finish(sha512s(res.hashable));
const rksSign = (s: bigint, P: Bytes, rBytes: Bytes, msg: Bytes): Finishable<Bytes> => { // for sign
  const r = modL_LE(rBytes);                            // r was created outside, reduce it modulo L
  const R = G.mul(r).toRawBytes();                      // R = [r]B
  const hashable = concatB(R, P, msg);                  // dom2(F, C) || R || A || PH(M)
  const finish = (hashed: Bytes): Bytes => {            // k = SHA512(dom2(F, C) || R || A || PH(M))
    const S = mod(r + modL_LE(hashed) * s, N);          // S = (r + k * s) mod L; 0 <= s < l
    return u8(concatB(R, n2b_32LE(S)), 64)              // 64-byte sig: 32b R.x + 32b LE(S)
  }
  return { hashable, finish }
};
const signAsync = async (msg: Hex, privKey: Hex): Promise<Bytes> => {
  const m = toU8(msg);                                  // RFC8032 5.1.6: sign msg with key async
  const { prefix, scalar: s, pointBytes: P } = await extendedPubAsync(privKey); // calc pub, prefix
  const rBytes = await sha512a(prefix, m);              // r = SHA512(dom2(F, C) || prefix || PH(M))
  return await hashFinishA(rksSign(s, P, rBytes, m));   // Generate R, k, S, then 64-byte signature
};
const signSync = (msg: Hex, privKey: Hex): Bytes => {
  const m = toU8(msg);                                  // RFC8032 5.1.6: sign msg with key sync
  const { prefix, scalar: s, pointBytes: P } = extendedPubSync(privKey); // calc pub, prefix
  const rBytes = sha512s(prefix, m);                    // r = SHA512(dom2(F, C) || prefix || PH(M))
  return hashFinishS(rksSign(s, P, rBytes, m));         // Generate R, k, S, then 64-byte signature
};
const verif = (sig: Hex, msg: Hex, pub: PubKey): Finishable<boolean> => {
  msg = toU8(msg);                                      // Message hex str/Bytes
  sig = toU8(sig, 64);                                  // Signature hex str/Bytes, must be 64 bytes
  const A = pub instanceof Point ? pub : Point.fromHex(pub, false); // public key A decoded
  const R = Point.fromHex(sig.slice(0, 32), false);     // 0 <= R < 2^256: ZIP215 R can be >= P
  const s = b2n_LE(sig.slice(32, 64));                  // Decode second half as an integer S
  const SB = G.mul(s, false);                           // in the range 0 <= s < L
  const hashable = concatB(R.toRawBytes(), A.toRawBytes(), msg); // dom2(F, C) || R || A || PH(M)
  const finish = (hashed: Bytes): boolean => {          // k = SHA512(dom2(F, C) || R || A || PH(M))
    const k = modL_LE(hashed);                          // decode in little-endian, modulo L
    const RkA = R.add(A.mul(k, false));                 // [8]R + [8][k]A'
    return RkA.sub(SB).clearCofactor().eql(Point.ZERO); // [8][S]B = [8]R + [8][k]A'
  }
  return { hashable, finish };
};
const verifyAsync = async (sig: Hex, msg: Hex, pubKey: PubKey): Promise<boolean> =>
  await hashFinishA(verif(sig, msg, pubKey))            // RFC8032 5.1.7: verification async
const verifySync = (sig: Hex, msg: Hex, pubKey: PubKey): boolean =>
  hashFinishS(verif(sig, msg, pubKey))                  // RFC8032 5.1.7: verification sync

declare const globalThis: Record<string, any> | undefined;
const cr: { node?: any; web?: any } = {
  node: typeof require === 'function' && require('crypto'), // node.js require('crypto')
  web: typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined,
};
const utils = {
  getExtendedPublicKeyAsync: extendedPubAsync,
  getExtendedPublicKey: extendedPubSync,

  bytesToHex: b2h, hexToBytes: h2b,
  concatBytes: concatB, mod, invert: inv,
  randomBytes: (len: number): Bytes => {                // CSPRNG (random number generator)
    return cr.web ? cr.web.getRandomValues(u8n(len)) :
      cr.node ? u8fr(cr.node.randomBytes(len)) : err('CSPRNG not present');// throw when unavailable
  },
  randomPrivateKey: (): Bytes => utils.randomBytes(32),
  precompute() {},
  sha512Async: async (...messages: Bytes[]): Promise<Bytes> => {
    const m = concatB(...messages);
    return cr.web ? u8n(await cr.web.subtle.digest('SHA-512', m.buffer)) :
      cr.node ? u8fr(cr.node.createHash('sha512').update(m).digest()) :
      err('utils.sha512 not set');
  },
  sha512Sync: undefined as Sha512FnSync,                // Actual logic below
};
Object.defineProperties(utils, { sha512Sync: {  // Allow setting it once. Next sets will be ignored
  configurable: false, get() { return _shaS; }, set(f) { if (!_shaS) _shaS = f; },
} });
const W = 8;                                            // Precomputes-related code. W = window size
const precompute = () => {                              // They give 12x faster getPublicKey(),
  const points: Point[] = [];                           // 10x sign(), 2x verify(). To achieve this,
  const windows = 256 / W + 1;                          // app needs to spend 40ms+ to calculate
  let p = G, b = p;                                     // 65536 points related to base point G.
  for (let w = 0; w < windows; w++) {                   // Points are stored in array and used
    b = p;                                              // any time Gx multiplication is done.
    points.push(b);                                     // They consume 16-32 MiB of RAM.
    for (let i = 1; i < 2 ** (W - 1); i++) { b = b.add(p); points.push(b); }
    p = b.dbl();                                        // Precomputes don't speed-up getSharedKey,
  }                                                     // which multiplies user point by scalar,
  return points;                                        // when precomputes are using base point
}
const wNAF = (n: bigint): { p: Point; f: Point } => {   // w-ary non-adjacent form (wNAF) method.
                                                        // Compared to other point mult methods,
  const comp = Gpows || (Gpows = precompute());         // stores 2x less points using subtraction
  const neg = (cnd: boolean, p: Point) => { let n = p.neg(); return cnd ? n : p; } // negate
  let p = I, f = G;                                     // f must be G, or could become I in the end
  const windows = 1 + 256 / W;                          // W=8 17 windows
  const wsize = 2 ** (W - 1);                           // W=8 128 window size
  const mask = BigInt(2 ** W - 1);                      // W=8 will create mask 0b11111111
  const maxNum = 2 ** W;                                // W=8 256
  const shiftBy = BigInt(W);                            // W=8 8
  for (let w = 0; w < windows; w++) {
    const off = w * wsize;
    let wbits = Number(n & mask);                       // extract W bits.
    n >>= shiftBy;                                      // shift number by W bits.
    if (wbits > wsize) { wbits -= maxNum; n += 1n; }    // split if bits > max: +224 => 256-32
    const off1 = off, off2 = off + Math.abs(wbits) - 1; // offsets, evaluate both
    const cnd1 = w % 2 !== 0, cnd2 = wbits < 0;         // conditions, evaluate both
    if (wbits === 0) {
      f = f.add(neg(cnd1, comp[off1]));                 // bits are 0: add garbage to fake point
    } else {                                            //          ^ can't add off2, off2 = I
      p = p.add(neg(cnd2, comp[off2]));                 // bits are 1: add to result point
    }
  }
  return { p, f }                                       // return both real and fake points for JIT
};        // !! you can disable precomputes by commenting-out call of the wNAF() inside Point#mul()
export {
  pubSync as getPublicKey, signSync as sign, verifySync as verify, // sync
  pubAsync as getPublicKeyAsync, signAsync, verifyAsync, // async
  CURVE, utils, Point as ExtendedPoint
}

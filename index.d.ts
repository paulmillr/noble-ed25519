/**
 * ed25519 curve parameters. Equation is −x² + y² = -a + dx²y².
 * Gx and Gy are generator coordinates. p is field order, n is group order.
 * h is cofactor.
 */
declare const CURVE: {
    a: bigint;
    d: bigint;
    p: bigint;
    n: bigint;
    h: number;
    Gx: bigint;
    Gy: bigint;
};
/** Alias to Uint8Array. */
export type Bytes = Uint8Array;
/** Hex-encoded string or Uint8Array. */
export type Hex = Bytes | string;
/** Point in 2d xy affine coordinates. */
export interface AffinePoint {
    x: bigint;
    y: bigint;
}
/** Point in xyzt extended coordinates. */
declare class Point {
    readonly ex: bigint;
    readonly ey: bigint;
    readonly ez: bigint;
    readonly et: bigint;
    constructor(ex: bigint, ey: bigint, ez: bigint, et: bigint);
    static readonly BASE: Point;
    static readonly ZERO: Point;
    static fromAffine(p: AffinePoint): Point;
    static fromHex(hex: Hex, zip215?: boolean): Point;
    get x(): bigint;
    get y(): bigint;
    equals(other: Point): boolean;
    is0(): boolean;
    negate(): Point;
    double(): Point;
    add(other: Point): Point;
    mul(n: bigint, safe?: boolean): Point;
    multiply(scalar: bigint): Point;
    clearCofactor(): Point;
    isSmallOrder(): boolean;
    isTorsionFree(): boolean;
    toAffine(): AffinePoint;
    toRawBytes(): Bytes;
    toHex(): string;
}
type Sha512FnSync = undefined | ((...messages: Bytes[]) => Bytes);
type ExtK = {
    head: Bytes;
    prefix: Bytes;
    scalar: bigint;
    point: Point;
    pointBytes: Bytes;
};
/** Creates 32-byte ed25519 public key from 32-byte private key. Async. */
declare const getPublicKeyAsync: (priv: Hex) => Promise<Bytes>;
/** Creates 32-byte ed25519 public key from 32-byte private key. To use, set `etc.sha512Sync` first. */
declare const getPublicKey: (priv: Hex) => Bytes;
/** Signs message (NOT message hash) using private key. Async. */
declare const signAsync: (msg: Hex, privKey: Hex) => Promise<Bytes>;
/** Signs message (NOT message hash) using private key. To use, set `etc.sha512Sync` first. */
declare const sign: (msg: Hex, privKey: Hex) => Bytes;
export type DVO = {
    zip215?: boolean;
};
/** Verifies signature on message and public key. Async. */
declare const verifyAsync: (s: Hex, m: Hex, p: Hex, opts?: DVO) => Promise<boolean>;
/** Verifies signature on message and public key. To use, set `etc.sha512Sync` first. */
declare const verify: (s: Hex, m: Hex, p: Hex, opts?: DVO) => boolean;
/** Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves. */
declare const etc: {
    bytesToHex: (b: Bytes) => string;
    hexToBytes: (hex: string) => Bytes;
    concatBytes: (...arrs: Bytes[]) => Uint8Array;
    mod: (a: bigint, b?: bigint) => bigint;
    invert: (num: bigint, md: bigint) => bigint;
    randomBytes: (len?: number) => Bytes;
    sha512Async: (...messages: Bytes[]) => Promise<Bytes>;
    sha512Sync: Sha512FnSync;
};
/** ed25519-specific key utilities. */
declare const utils: {
    getExtendedPublicKeyAsync: (priv: Hex) => Promise<ExtK>;
    getExtendedPublicKey: (priv: Hex) => ExtK;
    randomPrivateKey: () => Bytes;
    precompute: (w?: number, p?: Point) => Point;
};
export { getPublicKey, getPublicKeyAsync, sign, verify, // Remove the export to easily use in REPL
signAsync, verifyAsync, CURVE, etc, utils, Point as ExtendedPoint };

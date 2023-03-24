declare const CURVE: {
    a: bigint;
    d: bigint;
    p: bigint;
    n: bigint;
    h: number;
    Gx: bigint;
    Gy: bigint;
};
type Bytes = Uint8Array;
type Hex = Bytes | string;
interface AffinePoint {
    x: bigint;
    y: bigint;
}
declare class Point {
    readonly ex: bigint;
    readonly ey: bigint;
    readonly ez: bigint;
    readonly et: bigint;
    constructor(ex: bigint, ey: bigint, ez: bigint, et: bigint);
    static readonly BASE: Point;
    static readonly ZERO: Point;
    static fromAffine(p: AffinePoint): Point;
    static fromHex(hex: Hex, strict?: boolean): Point;
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
declare const getPublicKeyAsync: (priv: Hex) => Promise<Bytes>;
declare const getPublicKey: (priv: Hex) => Bytes;
declare const signAsync: (msg: Hex, privKey: Hex) => Promise<Bytes>;
declare const sign: (msg: Hex, privKey: Hex) => Bytes;
declare const verifyAsync: (s: Hex, m: Hex, p: Hex) => Promise<boolean>;
declare const verify: (s: Hex, m: Hex, p: Hex) => boolean;
declare const etc: {
    bytesToHex: (b: Bytes) => string;
    hexToBytes: (hex: string) => Bytes;
    concatBytes: (...arrs: Bytes[]) => Uint8Array;
    mod: (a: bigint, b?: bigint) => bigint;
    invert: (num: bigint, md?: bigint) => bigint;
    randomBytes: (len: number) => Bytes;
    sha512Async: (...messages: Bytes[]) => Promise<Bytes>;
    sha512Sync: Sha512FnSync;
};
declare const utils: {
    getExtendedPublicKeyAsync: (priv: Hex) => Promise<ExtK>;
    getExtendedPublicKey: (priv: Hex) => ExtK;
    randomPrivateKey: () => Bytes;
    precompute(w?: number, p?: Point): Point;
};
export { getPublicKey, getPublicKeyAsync, sign, verify, // Remove the export to easily use in REPL
signAsync, verifyAsync, CURVE, etc, utils, Point as ExtendedPoint };

export declare const CURVE: {
    a: bigint;
    d: bigint;
    P: bigint;
    l: bigint;
    n: bigint;
    h: number;
    Gx: bigint;
    Gy: bigint;
};
type Bytes = Uint8Array;
type Hex = Bytes | string;
type PubKey = Hex | Point;
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
    get x(): bigint;
    get y(): bigint;
    eql(other: Point): boolean;
    neg(): Point;
    dbl(): Point;
    add(other: Point): Point;
    sub(p: Point): Point;
    mul(n: bigint, safe?: boolean): Point;
    multiply(scalar: bigint): Point;
    clearCofactor(): Point;
    isSmallOrder(): boolean;
    isTorsionFree(): boolean;
    aff(): AffinePoint;
    static fromHex(hex: Hex, strict?: boolean): Point;
    toRawBytes(): Bytes;
    toHex(): string;
}
export declare const ExtendedPoint: typeof Point;
type Sha512FnSync = undefined | ((...messages: Bytes[]) => Bytes);
type ExtK = {
    head: Bytes;
    prefix: Bytes;
    scalar: bigint;
    point: Point;
    pointBytes: Bytes;
};
export declare const getPublicKeyAsync: (priv: Hex) => Promise<Bytes>;
export declare const getPublicKey: (priv: Hex) => Bytes;
export declare const signAsync: (msg: Hex, privKey: Hex) => Promise<Bytes>;
export declare const sign: (msg: Hex, privKey: Hex) => Bytes;
export declare const verifyAsync: (sig: Hex, msg: Hex, pubKey: PubKey) => Promise<boolean>;
export declare const verify: (sig: Hex, msg: Hex, pubKey: PubKey) => boolean;
export declare const etc: {
    bytesToHex: (b: Bytes) => string;
    hexToBytes: (hex: string) => Bytes;
    concatBytes: (...arrs: Bytes[]) => Uint8Array;
    mod: (a: bigint, b?: bigint) => bigint;
    invert: (num: bigint, md?: bigint) => bigint;
    randomBytes: (len: number) => Bytes;
    sha512Async: (...messages: Bytes[]) => Promise<Bytes>;
    sha512Sync: Sha512FnSync;
};
export declare const utils: {
    getExtendedPublicKeyAsync: (priv: Hex) => Promise<ExtK>;
    getExtendedPublicKey: (priv: Hex) => ExtK;
    precompute(p: Point, w?: number): Point;
    randomPrivateKey: () => Bytes;
};
export {};

/*! noble-ed25519 - MIT License (c) Paul Miller (paulmillr.com) */
declare const CURVE: {
    a: bigint;
    d: bigint;
    P: bigint;
    n: bigint;
    h: bigint;
    Gx: bigint;
    Gy: bigint;
};
export { CURVE };
declare type PubKey = Uint8Array | string | Point;
declare type Hex = Uint8Array | string;
declare type Signature = Uint8Array | string | SignResult;
declare class ExtendedPoint {
    x: bigint;
    y: bigint;
    z: bigint;
    t: bigint;
    static BASE: ExtendedPoint;
    static ZERO: ExtendedPoint;
    static fromAffine(p: Point): ExtendedPoint;
    constructor(x: bigint, y: bigint, z: bigint, t: bigint);
    static fromAffineBatch(points: ExtendedPoint[]): Point[];
    static fromUncompleteExtended(x: bigint, y: bigint, z: bigint, t: bigint): ExtendedPoint;
    static fromRistrettoHash(hash: Uint8Array): ExtendedPoint;
    private static elligatorRistrettoFlavor;
    static fromRistrettoBytes(bytes: Uint8Array): ExtendedPoint;
    toRistrettoRawBytes(): Uint8Array;
    equals(other: ExtendedPoint): boolean;
    negate(): ExtendedPoint;
    double(): ExtendedPoint;
    add(other: ExtendedPoint): ExtendedPoint;
    subtract(other: ExtendedPoint): ExtendedPoint;
    multiplyUnsafe(scalar: bigint): ExtendedPoint;
    toAffine(invZ?: bigint): Point;
}
declare class Point {
    x: bigint;
    y: bigint;
    static BASE: Point;
    static ZERO: Point;
    private WINDOW_SIZE?;
    constructor(x: bigint, y: bigint);
    _setWindowSize(windowSize: number): void;
    static fromHex(hash: Hex): Point;
    toRawBytes(): Uint8Array;
    toHex(): string;
    toX25519(): bigint;
    equals(other: Point): boolean;
    negate(): Point;
    add(other: Point): Point;
    subtract(other: Point): Point;
    private precomputeWindow;
    private wNAF;
    multiply(scalar: bigint, isAffine: false): ExtendedPoint;
    multiply(scalar: bigint, isAffine?: true): Point;
}
declare class SignResult {
    r: Point;
    s: bigint;
    constructor(r: Point, s: bigint);
    static fromHex(hex: Hex): SignResult;
    toRawBytes(): Uint8Array;
    toHex(): string;
}
export { ExtendedPoint, Point, SignResult };
export declare function invert(number: bigint, modulo?: bigint): bigint;
export declare function getPublicKey(privateKey: Uint8Array): Promise<Uint8Array>;
export declare function getPublicKey(privateKey: string): Promise<string>;
export declare function getPublicKey(privateKey: bigint | number): Promise<Uint8Array>;
export declare function sign(hash: Uint8Array, privateKey: Hex): Promise<Uint8Array>;
export declare function sign(hash: string, privateKey: Hex): Promise<string>;
export declare function verify(signature: Signature, hash: Hex, publicKey: PubKey): Promise<boolean>;
export declare const utils: {
    randomPrivateKey: (bytesLength?: number) => Uint8Array;
    sha512: (message: Uint8Array) => Promise<Uint8Array>;
    TORSION_SUBGROUP: string[];
    precompute(windowSize?: number, point?: Point): Point;
};

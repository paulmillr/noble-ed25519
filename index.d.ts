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
    static batchAffine(points: ExtendedPoint[]): Point[];
    static fromUncompleteExtended(x: bigint, y: bigint, z: bigint, t: bigint): ExtendedPoint;
    equals(other: ExtendedPoint): boolean;
    negate(): ExtendedPoint;
    double(): ExtendedPoint;
    add(other: ExtendedPoint): ExtendedPoint;
    subtract(other: ExtendedPoint): ExtendedPoint;
    multiplyUnsafe(scalar: bigint): ExtendedPoint;
    toAffine(invZ?: bigint): Point;
}
declare class RistrettoPoint {
    private point;
    static BASE: RistrettoPoint;
    static ZERO: RistrettoPoint;
    static fromHash(hash: Uint8Array): RistrettoPoint;
    private static elligatorRistrettoFlavor;
    static fromBytes(bytes: Uint8Array): RistrettoPoint;
    constructor(point: ExtendedPoint);
    toBytes(): Uint8Array;
    equals(other: RistrettoPoint): boolean;
    add(other: RistrettoPoint): RistrettoPoint;
    subtract(other: RistrettoPoint): RistrettoPoint;
    multiplyUnsafe(n: bigint): RistrettoPoint;
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
export { ExtendedPoint, RistrettoPoint, Point, SignResult };
export declare function modInverse(number: bigint, modulo?: bigint): bigint;
export declare function getPublicKey(privateKey: Uint8Array): Promise<Uint8Array>;
export declare function getPublicKey(privateKey: string): Promise<string>;
export declare function getPublicKey(privateKey: bigint | number): Promise<Uint8Array>;
export declare function sign(hash: Uint8Array, privateKey: Hex): Promise<Uint8Array>;
export declare function sign(hash: string, privateKey: Hex): Promise<string>;
export declare function verify(signature: Signature, hash: Hex, publicKey: PubKey): Promise<boolean>;
export declare const utils: {
    generateRandomPrivateKey: (bytesLength?: number) => Uint8Array;
    sha512: (message: Uint8Array) => Promise<Uint8Array>;
    precompute(windowSize?: number, point?: Point): Point;
};

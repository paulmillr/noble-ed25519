/*! noble-ed25519 - MIT License (c) Paul Miller (paulmillr.com) */
export declare const CURVE_PARAMS: {
    a: bigint;
    d: bigint;
    P: bigint;
    n: bigint;
    h: bigint;
    Gx: bigint;
    Gy: bigint;
};
declare type PubKey = Uint8Array | string | Point;
declare type Hex = Uint8Array | string;
declare type Signature = Uint8Array | string | SignResult;
declare class ExtendedPoint {
    x: bigint;
    y: bigint;
    z: bigint;
    t: bigint;
    static ZERO_POINT: ExtendedPoint;
    static fromPoint(p: Point): ExtendedPoint;
    constructor(x: bigint, y: bigint, z: bigint, t: bigint);
    static batchAffine(points: ExtendedPoint[]): Point[];
    equals(other: ExtendedPoint): boolean;
    negate(): ExtendedPoint;
    double(): ExtendedPoint;
    add(other: ExtendedPoint): ExtendedPoint;
    multiplyUnsafe(scalar: bigint): ExtendedPoint;
    toAffine(invZ?: bigint): Point;
}
export declare class Point {
    x: bigint;
    y: bigint;
    static BASE_POINT: Point;
    static ZERO_POINT: Point;
    private WINDOW_SIZE?;
    private PRECOMPUTES?;
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
    multiply(scalar: bigint, isAffine: false): ExtendedPoint;
    multiply(scalar: bigint, isAffine?: true): Point;
}
export declare class SignResult {
    r: Point;
    s: bigint;
    constructor(r: Point, s: bigint);
    static fromHex(hex: Hex): SignResult;
    toRawBytes(): Uint8Array;
    toHex(): string;
}
export declare const counters: {
    arrayToHex: number;
    numberToHex: number;
    hexToNumber: number;
    hexToArray: number;
    arrayToNumber: number;
    arrayToNumberLE: number;
};
export declare function getPublicKey(privateKey: Uint8Array): Promise<Uint8Array>;
export declare function getPublicKey(privateKey: string): Promise<string>;
export declare function getPublicKey(privateKey: bigint | number): Promise<Uint8Array>;
export declare function sign(hash: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
export declare function sign(hash: string, privateKey: string): Promise<string>;
export declare function verify(signature: Signature, hash: Hex, publicKey: PubKey): Promise<boolean>;
export declare const utils: {
    generateRandomPrivateKey: (bytesLength?: number) => Uint8Array;
    precompute(windowSize?: number, point?: Point): Point;
};
export {};

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
declare type PrivKey = Uint8Array | string | bigint | number;
declare type PubKey = Uint8Array | string | Point;
declare type Hex = Uint8Array | string;
declare type Signature = Uint8Array | string | SignResult;
declare class ProjectivePoint {
    x: bigint;
    y: bigint;
    z: bigint;
    static ZERO_POINT: ProjectivePoint;
    static fromPoint(p: Point): ProjectivePoint;
    constructor(x: bigint, y: bigint, z: bigint);
    static batchAffine(points: ProjectivePoint[]): Point[];
    equals(other: ProjectivePoint): boolean;
    add(other: ProjectivePoint): ProjectivePoint;
    double(): ProjectivePoint;
    multiplyUnsafe(scalar: bigint): ProjectivePoint;
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
    encode(): Uint8Array;
    toHex(): string;
    toX25519(): bigint;
    equals(other: Point): boolean;
    negate(): Point;
    add(other: Point): Point;
    subtract(other: Point): Point;
    private precomputeWindow;
    multiply(scalar: bigint, isAffine: false): ProjectivePoint;
    multiply(scalar: bigint, isAffine?: true): Point;
}
export declare class SignResult {
    r: Point;
    s: bigint;
    constructor(r: Point, s: bigint);
    static fromHex(hex: Hex): SignResult;
    toHex(): string;
}
export declare function getPublicKey(privateKey: Uint8Array): Promise<Uint8Array>;
export declare function getPublicKey(privateKey: string): Promise<string>;
export declare function getPublicKey(privateKey: bigint | number): Promise<Point>;
export declare function sign(hash: Uint8Array, privateKey: PrivKey): Promise<Uint8Array>;
export declare function sign(hash: string, privateKey: PrivKey): Promise<string>;
export declare function verify(signature: Signature, hash: Hex, publicKey: PubKey): Promise<boolean>;
export declare const utils: {
    precompute(windowSize?: number, point?: Point): Point;
};
export {};

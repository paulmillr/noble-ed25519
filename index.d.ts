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
declare type Hex = Uint8Array | string;
declare type PrivKey = Hex | bigint | number;
declare type PubKey = Hex | Point;
declare type SigType = Hex | Signature;
declare class ExtendedPoint {
    x: bigint;
    y: bigint;
    z: bigint;
    t: bigint;
    constructor(x: bigint, y: bigint, z: bigint, t: bigint);
    static BASE: ExtendedPoint;
    static ZERO: ExtendedPoint;
    static fromAffine(p: Point): ExtendedPoint;
    static toAffineBatch(points: ExtendedPoint[]): Point[];
    static normalizeZ(points: ExtendedPoint[]): ExtendedPoint[];
    static fromRistrettoHash(hash: Uint8Array): ExtendedPoint;
    private static calcElligatorRistrettoMap;
    static fromRistrettoBytes(bytes: Uint8Array): ExtendedPoint;
    toRistrettoBytes(): Uint8Array;
    equals(other: ExtendedPoint): boolean;
    negate(): ExtendedPoint;
    double(): ExtendedPoint;
    add(other: ExtendedPoint): ExtendedPoint;
    subtract(other: ExtendedPoint): ExtendedPoint;
    multiplyUnsafe(scalar: bigint): ExtendedPoint;
    private precomputeWindow;
    private wNAF;
    multiply(scalar: number | bigint, affinePoint?: Point): ExtendedPoint;
    toAffine(invZ?: bigint): Point;
}
declare class Point {
    x: bigint;
    y: bigint;
    static BASE: Point;
    static ZERO: Point;
    _WINDOW_SIZE?: number;
    constructor(x: bigint, y: bigint);
    _setWindowSize(windowSize: number): void;
    static fromHex(hash: Hex): Point;
    static fromPrivateKey(privateKey: PrivKey): Promise<Point>;
    toRawBytes(): Uint8Array;
    toHex(): string;
    toX25519(): bigint;
    equals(other: Point): boolean;
    negate(): Point;
    add(other: Point): Point;
    subtract(other: Point): Point;
    multiply(scalar: number | bigint): Point;
}
declare class Signature {
    r: Point;
    s: bigint;
    constructor(r: Point, s: bigint);
    static fromHex(hex: Hex): Signature;
    toRawBytes(): Uint8Array;
    toHex(): string;
}
export { ExtendedPoint, Point, Signature, Signature as SignResult };
export declare function getPublicKey(privateKey: Uint8Array | bigint | number): Promise<Uint8Array>;
export declare function getPublicKey(privateKey: string): Promise<string>;
export declare function sign(hash: Uint8Array, privateKey: Hex): Promise<Uint8Array>;
export declare function sign(hash: string, privateKey: Hex): Promise<string>;
export declare function verify(signature: SigType, hash: Hex, publicKey: PubKey): Promise<boolean>;
export declare const utils: {
    TORSION_SUBGROUP: string[];
    randomBytes: (bytesLength?: number) => Uint8Array;
    randomPrivateKey: () => Uint8Array;
    sha512: (message: Uint8Array) => Promise<Uint8Array>;
    precompute(windowSize?: number, point?: Point): Point;
};

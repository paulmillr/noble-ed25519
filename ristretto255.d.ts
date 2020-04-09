/*! noble-ristretto255 - MIT License (c) Paul Miller (paulmillr.com) */
export declare function modInverse(number: bigint, modulo?: bigint): bigint;
export declare function sqrtRatio(t: bigint, v: bigint): {
    isNotZeroSquare: boolean;
    value: bigint;
};
export declare const P: bigint;
export declare const PRIME_ORDER: bigint;
export declare class ProjectiveP1xP1 {
    x: bigint;
    y: bigint;
    z: bigint;
    T: bigint;
    static ZERO: ProjectiveP1xP1;
    constructor(x: bigint, y: bigint, z: bigint, T: bigint);
}
export declare class ProjectiveP2 {
    x: bigint;
    y: bigint;
    z: bigint;
    static fromP1xP1(point: ProjectiveP1xP1): ProjectiveP2;
    static fromP3(point: ProjectiveP3): ProjectiveP2;
    static ZERO: ProjectiveP2;
    constructor(x: bigint, y: bigint, z: bigint);
    double(): ProjectiveP1xP1;
}
export declare class ProjectiveP3 {
    x: bigint;
    y: bigint;
    z: bigint;
    T: bigint;
    static ZERO: ProjectiveP3;
    static fromP1xP1(point: ProjectiveP1xP1): ProjectiveP3;
    static fromP2(point: ProjectiveP2): ProjectiveP3;
    constructor(x: bigint, y: bigint, z: bigint, T: bigint);
    toProjectiveNielsPoint(): ProjectiveP3;
    toExtendedProjective(): ProjectiveP3;
    toExtendedCompleted(): ProjectiveP3;
    addCached(other: ProjectiveCached): ProjectiveP1xP1;
    subtractCached(other: ProjectiveCached): ProjectiveP1xP1;
    addAffine(other: AffineCached): ProjectiveP1xP1;
    subtractAffine(other: AffineCached): ProjectiveP1xP1;
    add(other: ProjectiveP3): ProjectiveP3;
    subtract(other: ProjectiveP3): ProjectiveP3;
    double(): ProjectiveP3;
    negative(): ProjectiveP3;
    multiply(n: bigint): ProjectiveP3;
    equals(other: ProjectiveP3): boolean;
}
export declare class ProjectiveCached {
    yPlusX: bigint;
    yMinusX: bigint;
    z: bigint;
    T2d: bigint;
    static ZERO(): ProjectiveCached;
    static fromP3(point: ProjectiveP3): ProjectiveCached;
    constructor(yPlusX: bigint, yMinusX: bigint, z: bigint, T2d: bigint);
}
export declare class AffineCached {
    yPlusX: bigint;
    yMinusX: bigint;
    T2d: bigint;
    static fromP3(point: ProjectiveP3): AffineCached;
    static ZERO(): AffineCached;
    constructor(yPlusX: bigint, yMinusX: bigint, T2d: bigint);
}
export declare let sha512: (a: Uint8Array) => Promise<Uint8Array>;
export declare function fromBytesLE(bytes: Uint8Array): bigint;
export declare function hexToBytes(hash: string): Uint8Array;
export declare function toBigInt(num: string | Uint8Array | bigint | number): bigint;
export declare function isBytesEquals(b1: Uint8Array, b2: Uint8Array): boolean;
export declare function numberToBytes(num: bigint): Uint8Array;
export declare function concatTypedArrays(...arrays: Uint8Array[]): Uint8Array;
export declare class RistrettoPoint {
    private point;
    static ZERO: RistrettoPoint;
    static fromHash(hash: Uint8Array): RistrettoPoint;
    private static elligatorRistrettoFlavor;
    static fromBytes(bytes: Uint8Array): RistrettoPoint;
    constructor(point: ProjectiveP3);
    toBytes(): Uint8Array;
    add(other: RistrettoPoint): RistrettoPoint;
    subtract(other: RistrettoPoint): RistrettoPoint;
    multiply(n: bigint): RistrettoPoint;
    equals(other: RistrettoPoint): boolean;
}
export declare const BASE_POINT: RistrettoPoint;

/*! noble-ristretto255 - MIT License (c) Paul Miller (paulmillr.com) */
export declare class FieldElement {
    static readonly P: bigint;
    static readonly D: FieldElement;
    static readonly D2: FieldElement;
    static readonly SQRT_M1: FieldElement;
    static readonly INVSQRT_A_MINUS_D: FieldElement;
    static readonly SQRT_AD_MINUS_ONE: FieldElement;
    static readonly PRIME_ORDER: bigint;
    private static load8;
    static fromBytes(bytes: Uint8Array): FieldElement;
    static one(): FieldElement;
    static zero(): FieldElement;
    static mod(a: bigint, b: bigint): bigint;
    readonly value: bigint;
    constructor(value: bigint);
    toBytesBE(length?: number): Uint8Array;
    toBytesLE(length?: number): Uint8Array;
    equals(other: FieldElement): boolean;
    isNegative(): boolean;
    isZero(): boolean;
    add(other: FieldElement): FieldElement;
    subtract(other: FieldElement): FieldElement;
    div(other: FieldElement): FieldElement;
    multiply(other: FieldElement): FieldElement;
    pow(power: bigint): FieldElement;
    pow2k(power: bigint): FieldElement;
    invert(): FieldElement;
    negative(): FieldElement;
    square(): FieldElement;
    private pow22501;
    private powP58;
    select(other: FieldElement, choice: 0n | 1n | 0 | 1 | boolean): FieldElement;
    condNegative(choice: 0n | 1n | 0 | 1 | boolean): FieldElement;
    condSwap(other: FieldElement, choice: 0n | 1n | 0 | 1 | boolean): FieldElement[];
    sqrtRatio(v: FieldElement): {
        isNotZeroSquare: boolean;
        value: FieldElement;
    };
    invertSqrt(): {
        isNotZeroSquare: boolean;
        value: FieldElement;
    };
}
export declare const P: bigint;
export declare const PRIME_ORDER: bigint;
export declare class ProjectiveP1xP1 {
    x: FieldElement;
    y: FieldElement;
    z: FieldElement;
    T: FieldElement;
    static zero(): ProjectiveP1xP1;
    constructor(x: FieldElement, y: FieldElement, z: FieldElement, T: FieldElement);
}
export declare class ProjectiveP2 {
    x: FieldElement;
    y: FieldElement;
    z: FieldElement;
    static fromP1xP1(point: ProjectiveP1xP1): ProjectiveP2;
    static fromP3(point: ProjectiveP3): ProjectiveP2;
    static zero(): ProjectiveP2;
    constructor(x: FieldElement, y: FieldElement, z: FieldElement);
    double(): ProjectiveP1xP1;
}
export declare class ProjectiveP3 {
    x: FieldElement;
    y: FieldElement;
    z: FieldElement;
    T: FieldElement;
    static fromP1xP1(point: ProjectiveP1xP1): ProjectiveP3;
    static fromP2(point: ProjectiveP2): ProjectiveP3;
    static one(): ProjectiveP3;
    constructor(x: FieldElement, y: FieldElement, z: FieldElement, T: FieldElement);
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
    yPlusX: FieldElement;
    yMinusX: FieldElement;
    z: FieldElement;
    T2d: FieldElement;
    static one(): ProjectiveCached;
    static fromP3(point: ProjectiveP3): ProjectiveCached;
    constructor(yPlusX: FieldElement, yMinusX: FieldElement, z: FieldElement, T2d: FieldElement);
    select(other: ProjectiveCached, cond: 0 | 1 | 0n | 1n | boolean): ProjectiveCached;
    condNegative(cond: 0 | 1 | 0n | 1n | boolean): ProjectiveCached;
}
export declare class AffineCached {
    yPlusX: FieldElement;
    yMinusX: FieldElement;
    T2d: FieldElement;
    static fromP3(point: ProjectiveP3): AffineCached;
    static one(): AffineCached;
    constructor(yPlusX: FieldElement, yMinusX: FieldElement, T2d: FieldElement);
    select(other: AffineCached, cond: 0 | 1 | 0n | 1n | boolean): AffineCached;
    condNegative(cond: 0 | 1 | 0n | 1n | boolean): AffineCached;
}
export declare let sha512: (a: Uint8Array) => Promise<Uint8Array>;
export declare function fromBytesLE(bytes: Uint8Array): bigint;
export declare function hexToBytes(hash: string): Uint8Array;
export declare function toBigInt(num: string | Uint8Array | bigint | number): bigint;
export declare function isBytesEquals(b1: Uint8Array, b2: Uint8Array): boolean;
export declare function numberToBytes(num: bigint): Uint8Array;
export declare function concatTypedArrays(...args: Uint8Array[]): Uint8Array;
export declare class RistrettoPoint {
    private point;
    static one(): RistrettoPoint;
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

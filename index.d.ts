/*! noble-secp256k1 - MIT License (c) Paul Miller (paulmillr.com) */
export declare const P: bigint;
export declare const PRIME_ORDER: bigint;
declare type PrivKey = Uint8Array | string | bigint | number;
declare type PubKey = Uint8Array | string | Point;
declare type Hex = Uint8Array | string;
declare type Signature = Uint8Array | string | SignResult;
export declare class Point {
    x: bigint;
    y: bigint;
    constructor(x: bigint, y: bigint);
    static fromHex(hash: Hex): Point;
    encode(): Uint8Array;
    toHex(): string;
}
export declare const BASE_POINT: Point;
export declare class SignResult {
    r: Point;
    s: bigint;
    constructor(r: Point, s: bigint);
    static fromHex(hex: Hex): SignResult;
    toHex(): string;
}
export declare function scalarmultBase(privateKey: Uint8Array): Uint8Array;
export declare function scalarmultBase(privateKey: string): string;
export declare function scalarmultBase(privateKey: bigint | number): Point;
export declare function getPublicKey(privateKey: Uint8Array): Promise<Uint8Array>;
export declare function getPublicKey(privateKey: string): Promise<string>;
export declare function getPublicKey(privateKey: bigint | number): Promise<Point>;
export declare function sign(hash: Uint8Array, privateKey: PrivKey, publicKey: PubKey): Promise<Uint8Array>;
export declare function sign(hash: string, privateKey: PrivKey, publicKey: PubKey): Promise<string>;
export declare function verify(signature: Signature, hash: Hex, publicKey: PubKey): Promise<boolean>;
export {};

/** Alias to Uint8Array. */
export type Bytes = Uint8Array;
/**
 * Bytes API type helpers for old + new TypeScript.
 *
 * TS 5.6 has `Uint8Array`, while TS 5.9+ made it generic `Uint8Array<ArrayBuffer>`.
 * We can't use specific return type, because TS 5.6 will error.
 * We can't use generic return type, because most TS 5.9 software will expect specific type.
 *
 * Maps typed-array input leaves to broad forms.
 * These are compatibility adapters, not ownership guarantees.
 *
 * - `TArg` keeps byte inputs broad.
 * - `TRet` marks byte outputs for TS 5.6 and TS 5.9+ compatibility.
 */
export type TypedArg<T> = T extends BigInt64Array ? BigInt64Array : T extends BigUint64Array ? BigUint64Array : T extends Float32Array ? Float32Array : T extends Float64Array ? Float64Array : T extends Int16Array ? Int16Array : T extends Int32Array ? Int32Array : T extends Int8Array ? Int8Array : T extends Uint16Array ? Uint16Array : T extends Uint32Array ? Uint32Array : T extends Uint8ClampedArray ? Uint8ClampedArray : T extends Uint8Array ? Uint8Array : never;
/** Maps typed-array output leaves to narrow TS-compatible forms. */
export type TypedRet<T> = T extends BigInt64Array ? ReturnType<typeof BigInt64Array.of> : T extends BigUint64Array ? ReturnType<typeof BigUint64Array.of> : T extends Float32Array ? ReturnType<typeof Float32Array.of> : T extends Float64Array ? ReturnType<typeof Float64Array.of> : T extends Int16Array ? ReturnType<typeof Int16Array.of> : T extends Int32Array ? ReturnType<typeof Int32Array.of> : T extends Int8Array ? ReturnType<typeof Int8Array.of> : T extends Uint16Array ? ReturnType<typeof Uint16Array.of> : T extends Uint32Array ? ReturnType<typeof Uint32Array.of> : T extends Uint8ClampedArray ? ReturnType<typeof Uint8ClampedArray.of> : T extends Uint8Array ? ReturnType<typeof Uint8Array.of> : never;
/** Recursively adapts byte-carrying API input types. See {@link TypedArg}. */
export type TArg<T> = T | ([TypedArg<T>] extends [never] ? T extends (...args: infer A) => infer R ? ((...args: {
    [K in keyof A]: TRet<A[K]>;
}) => TArg<R>) & {
    [K in keyof T]: T[K] extends (...args: any) => any ? T[K] : TArg<T[K]>;
} : T extends [infer A, ...infer R] ? [TArg<A>, ...{
    [K in keyof R]: TArg<R[K]>;
}] : T extends readonly [infer A, ...infer R] ? readonly [TArg<A>, ...{
    [K in keyof R]: TArg<R[K]>;
}] : T extends (infer A)[] ? TArg<A>[] : T extends readonly (infer A)[] ? readonly TArg<A>[] : T extends Promise<infer A> ? Promise<TArg<A>> : T extends object ? {
    [K in keyof T]: TArg<T[K]>;
} : T : TypedArg<T>);
/** Recursively adapts byte-carrying API output types. See {@link TypedArg}. */
export type TRet<T> = T extends unknown ? T & ([TypedRet<T>] extends [never] ? T extends (...args: infer A) => infer R ? ((...args: {
    [K in keyof A]: TArg<A[K]>;
}) => TRet<R>) & {
    [K in keyof T]: T[K] extends (...args: any) => any ? T[K] : TRet<T[K]>;
} : T extends [infer A, ...infer R] ? [TRet<A>, ...{
    [K in keyof R]: TRet<R[K]>;
}] : T extends readonly [infer A, ...infer R] ? readonly [TRet<A>, ...{
    [K in keyof R]: TRet<R[K]>;
}] : T extends (infer A)[] ? TRet<A>[] : T extends readonly (infer A)[] ? readonly TRet<A>[] : T extends Promise<infer A> ? Promise<TRet<A>> : T extends object ? {
    [K in keyof T]: TRet<T[K]>;
} : T : TypedRet<T>) : never;
/** Edwards elliptic curve options. */
export type EdwardsOpts = Readonly<{
    /** Prime field modulus. */
    p: bigint;
    /** Group order. */
    n: bigint;
    /** Curve cofactor. */
    h: bigint;
    /** Edwards curve parameter `a`. */
    a: bigint;
    /** Edwards curve parameter `d`. */
    d: bigint;
    /** Generator x coordinate. */
    Gx: bigint;
    /** Generator y coordinate. */
    Gy: bigint;
}>;
/** Canonical modular reduction into `[0, b)`. */
declare const M: (a: bigint, b?: bigint) => bigint;
/** Modular inversion using Euclidean GCD (non-CT) instead of the RFC's `x^(p-2)` formulation.
 * This still sits on secret-dependent paths like point normalization during keygen/signing. */
declare const invert: (num: bigint, md: bigint) => bigint;
/**
 * SHA-512 helper used by the synchronous API.
 * @param msg - Message bytes to hash.
 * @returns 64-byte SHA-512 digest.
 * @example
 * Hash message bytes after wiring the synchronous SHA-512 implementation.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 * import { sha512 } from '@noble/hashes/sha2.js';
 *
 * ed.hashes.sha512 = sha512;
 * const digest = ed.hash(new Uint8Array([1, 2, 3]));
 * ```
 */
declare const hash: (msg: TArg<Bytes>) => TRet<Bytes>;
/** Point in 2d xy affine coordinates. */
export type AffinePoint = {
    /** Affine x coordinate. */
    x: bigint;
    /** Affine y coordinate. */
    y: bigint;
};
/**
 * Point in XYZT extended coordinates.
 * @param X - X coordinate.
 * @param Y - Y coordinate.
 * @param Z - Projective Z coordinate.
 * @param T - Cached cross-product term.
 * @example
 * Do point arithmetic with the built-in base point and encode the result as hex.
 *
 * ```ts
 * const hex = Point.BASE.double().toHex();
 * ```
 */
declare class Point {
    static BASE: Point;
    static ZERO: Point;
    readonly X: bigint;
    readonly Y: bigint;
    readonly Z: bigint;
    readonly T: bigint;
    constructor(X: bigint, Y: bigint, Z: bigint, T: bigint);
    static CURVE(): EdwardsOpts;
    static fromAffine(p: AffinePoint): Point;
    /** RFC8032 5.1.3: Bytes to Point. */
    static fromBytes(hex: TArg<Bytes>, zip215?: boolean): Point;
    static fromHex(hex: string, zip215?: boolean): Point;
    get x(): bigint;
    get y(): bigint;
    /** Checks if the point is valid and on-curve. */
    assertValidity(): this;
    /** Equality check: compare points P&Q. */
    equals(other: Point): boolean;
    is0(): boolean;
    /** Flip point over y coordinate. */
    negate(): Point;
    /** Point doubling. Complete formula. Cost: `4M + 4S + 1*a + 6add + 1*2`. */
    double(): Point;
    /** Point addition. Complete formula. Cost: `8M + 1*k + 8add + 1*2`. */
    add(other: Point): Point;
    subtract(other: Point): Point;
    /**
     * Point-by-scalar multiplication. Safe mode requires `1 <= n < CURVE.n`.
     * Unsafe mode additionally permits `n = 0` and returns the identity point for that case.
     * Uses {@link wNAF} for base point.
     * Uses fake point to mitigate side-channel leakage.
     * @param n - scalar by which point is multiplied
     * @param safe - safe mode guards against timing attacks; unsafe mode is faster
     */
    multiply(n: bigint, safe?: boolean): Point;
    multiplyUnsafe(scalar: bigint): Point;
    /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
    toAffine(): AffinePoint;
    toBytes(): TRet<Bytes>;
    toHex(): string;
    clearCofactor(): Point;
    isSmallOrder(): boolean;
    isTorsionFree(): boolean;
}
type ExtK = {
    head: Bytes;
    prefix: Bytes;
    scalar: bigint;
    point: Point;
    pointBytes: Bytes;
};
declare const getExtendedPublicKeyAsync: (secretKey: TArg<Bytes>) => Promise<TRet<ExtK>>;
declare const getExtendedPublicKey: (secretKey: TArg<Bytes>) => TRet<ExtK>;
/**
 * Creates a 32-byte Ed25519 public key from the RFC 8032 32-byte secret-key seed. Async.
 * @param secretKey - 32-byte RFC 8032 secret-key seed, not a 64-byte expanded secret key.
 * @returns 32-byte public key.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Derive the public key bytes for a newly generated signer secret.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 *
 * const secretKey = ed.utils.randomSecretKey();
 * const publicKey = await ed.getPublicKeyAsync(secretKey);
 * ```
 */
declare const getPublicKeyAsync: (secretKey: TArg<Bytes>) => Promise<TRet<Bytes>>;
/**
 * Creates a 32-byte Ed25519 public key from the RFC 8032 32-byte secret-key seed.
 * To use, set `hashes.sha512` first.
 * @param priv - 32-byte RFC 8032 secret-key seed, not a 64-byte expanded secret key.
 * @returns 32-byte public key.
 * @throws If synchronous SHA-512 has not been configured in `hashes`. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Derive the public key entirely through the synchronous API.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 * import { sha512 } from '@noble/hashes/sha2.js';
 *
 * ed.hashes.sha512 = sha512;
 * const secretKey = ed.utils.randomSecretKey();
 * const publicKey = ed.getPublicKey(secretKey);
 * ```
 */
declare const getPublicKey: (priv: TArg<Bytes>) => TRet<Bytes>;
/**
 * Signs message using secret key. Async.
 * Follows RFC8032 5.1.6.
 * @param message - Message bytes to sign.
 * @param secretKey - 32-byte RFC 8032 secret-key seed, not a 64-byte expanded secret key.
 * @returns 64-byte Ed25519 signature.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Sign an arbitrary message with a fresh Ed25519 secret key.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 *
 * const secretKey = ed.utils.randomSecretKey();
 * const message = new Uint8Array([1, 2, 3]);
 * const signature = await ed.signAsync(message, secretKey);
 * ```
 */
declare const signAsync: (message: TArg<Bytes>, secretKey: TArg<Bytes>) => Promise<TRet<Bytes>>;
/**
 * Signs message using secret key. To use, set `hashes.sha512` first.
 * Follows RFC8032 5.1.6.
 * @param message - Message bytes to sign.
 * @param secretKey - 32-byte RFC 8032 secret-key seed, not a 64-byte expanded secret key.
 * @returns 64-byte Ed25519 signature.
 * @throws If synchronous SHA-512 has not been configured in `hashes`. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Use the sync API when you've wired a SHA-512 implementation yourself.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 * import { sha512 } from '@noble/hashes/sha2.js';
 *
 * ed.hashes.sha512 = sha512;
 * const secretKey = ed.utils.randomSecretKey();
 * const signature = ed.sign(new Uint8Array([1, 2, 3]), secretKey);
 * ```
 */
declare const sign: (message: TArg<Bytes>, secretKey: TArg<Bytes>) => TRet<Bytes>;
/**
 * Verification options. zip215: true (default) follows ZIP215 spec. false would follow RFC8032.
 *
 * Any message with pubkey from `ED25519_TORSION_SUBGROUP` would be valid in sigs under ZIP215.
 */
export type EdDSAVerifyOpts = {
    /** Whether to use ZIP215 verification semantics instead of the library's stricter branch. */
    zip215?: boolean;
};
/**
 * Verifies a signature on message and public key. Async.
 * The implementation is based on RFC8032 5.1.7, but default opts use ZIP-215 semantics; pass
 * `{ zip215: false }` for the library's stricter branch.
 * @param signature - 64-byte signature.
 * @param message - Signed message bytes.
 * @param publicKey - 32-byte public key.
 * @param opts - Verification options. Defaults to ZIP-215 semantics. See {@link EdDSAVerifyOpts}.
 * @returns `true` when the signature is valid.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Verify the signature against the same message and derived public key.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 *
 * const secretKey = ed.utils.randomSecretKey();
 * const message = new Uint8Array([1, 2, 3]);
 * const publicKey = await ed.getPublicKeyAsync(secretKey);
 * const signature = await ed.signAsync(message, secretKey);
 * const isValid = await ed.verifyAsync(signature, message, publicKey);
 * ```
 */
declare const verifyAsync: (signature: TArg<Bytes>, message: TArg<Bytes>, publicKey: TArg<Bytes>, opts?: TArg<EdDSAVerifyOpts>) => Promise<boolean>;
/**
 * Verifies a signature on message and public key using the synchronous hash path.
 * The implementation is based on RFC8032 5.1.7, but default opts use ZIP-215 semantics; pass
 * `{ zip215: false }` for the library's stricter branch.
 * @param signature - 64-byte signature.
 * @param message - Signed message bytes.
 * @param publicKey - 32-byte public key.
 * @param opts - Verification options. Defaults to ZIP-215 semantics. See {@link EdDSAVerifyOpts}.
 * @returns `true` when the signature is valid.
 * @throws If synchronous SHA-512 has not been configured in `hashes`. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Verify a signature entirely through the synchronous API.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 * import { sha512 } from '@noble/hashes/sha2.js';
 *
 * ed.hashes.sha512 = sha512;
 * const secretKey = ed.utils.randomSecretKey();
 * const message = new Uint8Array([1, 2, 3]);
 * const publicKey = ed.getPublicKey(secretKey);
 * const signature = ed.sign(message, secretKey);
 * const isValid = ed.verify(signature, message, publicKey);
 * ```
 */
declare const verify: (signature: TArg<Bytes>, message: TArg<Bytes>, publicKey: TArg<Bytes>, opts?: TArg<EdDSAVerifyOpts>) => boolean;
/**
 * Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves.
 * Exposes the same low-level field-default `mod` reducer and non-CT `invert` helper used
 * internally.
 * @example
 * Convert bytes to a hex string with the low-level helper namespace.
 *
 * ```ts
 * const hex = etc.bytesToHex(new Uint8Array([1, 2, 3]));
 * ```
 */
declare const etc: {
    bytesToHex: (bytes: TArg<Bytes>) => string;
    hexToBytes: (hex: string) => TRet<Bytes>;
    concatBytes: (...arrs: TArg<Bytes[]>) => TRet<Bytes>;
    mod: typeof M;
    invert: typeof invert;
    randomBytes: (len?: number) => TRet<Bytes>;
};
/**
 * Hash implementations used by the synchronous API plus the default async WebCrypto provider.
 * Both slots are configurable API surface; wrapper helpers revalidate that providers still return
 * 64-byte SHA-512 digests.
 * @example
 * Provide a SHA-512 implementation before calling synchronous helpers.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 * import { sha512 } from '@noble/hashes/sha2.js';
 *
 * ed.hashes.sha512 = sha512;
 * const { publicKey } = ed.keygen();
 * ```
 */
declare const hashes: {
    sha512Async: (message: TArg<Bytes>) => Promise<TRet<Bytes>>;
    sha512: undefined | ((message: TArg<Bytes>) => TRet<Bytes>);
};
declare const randomSecretKey: (seed?: TArg<Bytes>) => TRet<Bytes>;
type KeysSecPub = {
    secretKey: Bytes;
    publicKey: Bytes;
};
/**
 * Generates a secret/public keypair.
 * @param seed - Optional 32-byte Ed25519 secret-key seed, returned verbatim as `secretKey`.
 * @returns Keypair with `secretKey` and `publicKey`.
 * @throws If synchronous SHA-512 has not been configured in `hashes`. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Generate a new keypair through the synchronous API after wiring SHA-512.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 * import { sha512 } from '@noble/hashes/sha2.js';
 *
 * ed.hashes.sha512 = sha512;
 * const { secretKey, publicKey } = ed.keygen();
 * ```
 */
declare const keygen: (seed?: TArg<Bytes>) => TRet<KeysSecPub>;
/**
 * Generates a secret/public keypair asynchronously.
 * @param seed - Optional 32-byte Ed25519 secret-key seed, returned verbatim as `secretKey`.
 * @returns Keypair with `secretKey` and `publicKey`.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Generate a new keypair through the asynchronous WebCrypto-backed path.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 *
 * const { secretKey, publicKey } = await ed.keygenAsync();
 * ```
 */
declare const keygenAsync: (seed?: TArg<Bytes>) => Promise<TRet<KeysSecPub>>;
/**
 * Ed25519-specific key utilities.
 * `utils.getExtendedPublicKey*` expose secret-derived internals (`head`, `prefix`, `scalar`, and
 * point objects), not just public-key bytes.
 * @example
 * Generate a new Ed25519 secret key and derive the matching public key.
 *
 * ```ts
 * import * as ed from '@noble/ed25519';
 *
 * const secretKey = ed.utils.randomSecretKey();
 * const publicKey = await ed.getPublicKeyAsync(secretKey);
 * ```
 */
declare const utils: {
    getExtendedPublicKeyAsync: typeof getExtendedPublicKeyAsync;
    getExtendedPublicKey: typeof getExtendedPublicKey;
    randomSecretKey: typeof randomSecretKey;
};
export { etc, getPublicKey, getPublicKeyAsync, hash, hashes, keygen, keygenAsync, Point, sign, signAsync, utils, verify, verifyAsync };

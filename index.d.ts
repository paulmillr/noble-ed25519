/** Alias to Uint8Array. */
export type Bytes = Uint8Array;
/** Hex-encoded string or Uint8Array. */
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
declare const bytesToHex: (b: Bytes) => string;
declare const hexToBytes: (hex: string) => Bytes;
declare const concatBytes: (...arrs: Bytes[]) => Bytes;
/** WebCrypto OS-level CSPRNG (random number generator). Will throw when not available. */
declare const randomBytes: (len?: number) => Bytes;
/** modular division */
declare const M: (a: bigint, b?: bigint) => bigint;
/** Modular inversion using euclidean GCD (non-CT). No negative exponent for now. */
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
declare const hash: (msg: Bytes) => Bytes;
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
    /** RFC8032 5.1.3: Uint8Array to Point. */
    static fromBytes(hex: Bytes, zip215?: boolean): Point;
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
     * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
     * Uses {@link wNAF} for base point.
     * Uses fake point to mitigate side-channel leakage.
     * @param n - scalar by which point is multiplied
     * @param safe - safe mode guards against timing attacks; unsafe mode is faster
     */
    multiply(n: bigint, safe?: boolean): Point;
    multiplyUnsafe(scalar: bigint): Point;
    /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
    toAffine(): AffinePoint;
    toBytes(): Bytes;
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
declare const getExtendedPublicKeyAsync: (secretKey: Bytes) => Promise<ExtK>;
declare const getExtendedPublicKey: (secretKey: Bytes) => ExtK;
/**
 * Creates 32-byte ed25519 public key from 32-byte secret key. Async.
 * @param secretKey - 32-byte secret key.
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
declare const getPublicKeyAsync: (secretKey: Bytes) => Promise<Bytes>;
/**
 * Creates 32-byte ed25519 public key from 32-byte secret key. To use, set `hashes.sha512` first.
 * @param priv - 32-byte secret key.
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
declare const getPublicKey: (priv: Bytes) => Bytes;
/**
 * Signs message using secret key. Async.
 * Follows RFC8032 5.1.6.
 * @param message - Message bytes to sign.
 * @param secretKey - 32-byte secret key.
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
declare const signAsync: (message: Bytes, secretKey: Bytes) => Promise<Bytes>;
/**
 * Signs message using secret key. To use, set `hashes.sha512` first.
 * Follows RFC8032 5.1.6.
 * @param message - Message bytes to sign.
 * @param secretKey - 32-byte secret key.
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
declare const sign: (message: Bytes, secretKey: Bytes) => Bytes;
/**
 * Verification options. zip215: true (default) follows ZIP215 spec. false would follow RFC8032.
 *
 * Any message with pubkey from `ED25519_TORSION_SUBGROUP` would be valid in sigs under ZIP215.
 */
export type EdDSAVerifyOpts = {
    /** Whether to use ZIP215 verification semantics instead of strict RFC8032 handling. */
    zip215?: boolean;
};
/**
 * Verifies signature on message and public key. Async.
 * Follows RFC8032 5.1.7.
 * @param signature - 64-byte signature.
 * @param message - Signed message bytes.
 * @param publicKey - 32-byte public key.
 * @param opts - Verification options. See {@link EdDSAVerifyOpts}.
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
declare const verifyAsync: (signature: Bytes, message: Bytes, publicKey: Bytes, opts?: EdDSAVerifyOpts) => Promise<boolean>;
/**
 * Verifies signature on message and public key using the synchronous hash path.
 * Follows RFC8032 5.1.7.
 * @param signature - 64-byte signature.
 * @param message - Signed message bytes.
 * @param publicKey - 32-byte public key.
 * @param opts - Verification options. See {@link EdDSAVerifyOpts}.
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
declare const verify: (signature: Bytes, message: Bytes, publicKey: Bytes, opts?: EdDSAVerifyOpts) => boolean;
/**
 * Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves.
 * @example
 * Convert bytes to a hex string with the low-level helper namespace.
 *
 * ```ts
 * const hex = etc.bytesToHex(new Uint8Array([1, 2, 3]));
 * ```
 */
declare const etc: {
    bytesToHex: typeof bytesToHex;
    hexToBytes: typeof hexToBytes;
    concatBytes: typeof concatBytes;
    mod: typeof M;
    invert: typeof invert;
    randomBytes: typeof randomBytes;
};
/**
 * Hash implementations used by the synchronous API.
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
    sha512Async: (message: Bytes) => Promise<Bytes>;
    sha512: undefined | ((message: Bytes) => Bytes);
};
declare const randomSecretKey: (seed?: Bytes) => Bytes;
type KeysSecPub = {
    secretKey: Bytes;
    publicKey: Bytes;
};
/**
 * Generates a secret/public keypair.
 * @param seed - Optional 32-byte seed.
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
declare const keygen: (seed?: Bytes) => KeysSecPub;
/**
 * Generates a secret/public keypair asynchronously.
 * @param seed - Optional 32-byte seed.
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
declare const keygenAsync: (seed?: Bytes) => Promise<KeysSecPub>;
/**
 * Ed25519-specific key utilities.
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

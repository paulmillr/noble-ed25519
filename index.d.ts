/** Alias to Uint8Array. */
export type Bytes = Uint8Array;
/** Hex-encoded string or Uint8Array. */
/** Edwards elliptic curve options. */
export type EdwardsOpts = Readonly<{
    p: bigint;
    n: bigint;
    h: bigint;
    a: bigint;
    d: bigint;
    Gx: bigint;
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
declare const hash: (msg: Bytes) => Bytes;
/** Point in 2d xy affine coordinates. */
export type AffinePoint = {
    x: bigint;
    y: bigint;
};
/** Point in XYZT extended coordinates. */
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
     * @param n scalar by which point is multiplied
     * @param safe safe mode guards against timing attacks; unsafe mode is faster
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
/** Creates 32-byte ed25519 public key from 32-byte secret key. Async. */
declare const getPublicKeyAsync: (secretKey: Bytes) => Promise<Bytes>;
/** Creates 32-byte ed25519 public key from 32-byte secret key. To use, set `hashes.sha512` first. */
declare const getPublicKey: (priv: Bytes) => Bytes;
/**
 * Signs message using secret key. Async.
 * Follows RFC8032 5.1.6.
 */
declare const signAsync: (message: Bytes, secretKey: Bytes) => Promise<Bytes>;
/**
 * Signs message using secret key. To use, set `hashes.sha512` first.
 * Follows RFC8032 5.1.6.
 */
declare const sign: (message: Bytes, secretKey: Bytes) => Bytes;
/** Verification options. zip215: true (default) follows ZIP215 spec. false would follow RFC8032. */
export type EdDSAVerifyOpts = {
    zip215?: boolean;
};
/** Verifies signature on message and public key. Async. Follows RFC8032 5.1.7. */
declare const verifyAsync: (signature: Bytes, message: Bytes, publicKey: Bytes, opts?: EdDSAVerifyOpts) => Promise<boolean>;
/** Verifies signature on message and public key. To use, set `hashes.sha512` first. Follows RFC8032 5.1.7. */
declare const verify: (signature: Bytes, message: Bytes, publicKey: Bytes, opts?: EdDSAVerifyOpts) => boolean;
/** Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves. */
declare const etc: {
    bytesToHex: typeof bytesToHex;
    hexToBytes: typeof hexToBytes;
    concatBytes: typeof concatBytes;
    mod: typeof M;
    invert: typeof invert;
    randomBytes: typeof randomBytes;
};
declare const hashes: {
    sha512Async: (message: Bytes) => Promise<Bytes>;
    sha512: undefined | ((message: Bytes) => Bytes);
};
declare const randomSecretKey: (seed?: Bytes) => Bytes;
type KeysSecPub = {
    secretKey: Bytes;
    publicKey: Bytes;
};
declare const keygen: (seed?: Bytes) => KeysSecPub;
declare const keygenAsync: (seed?: Bytes) => Promise<KeysSecPub>;
/** ed25519-specific key utilities. */
declare const utils: {
    getExtendedPublicKeyAsync: typeof getExtendedPublicKeyAsync;
    getExtendedPublicKey: typeof getExtendedPublicKey;
    randomSecretKey: typeof randomSecretKey;
};
export { etc, getPublicKey, getPublicKeyAsync, hash, hashes, keygen, keygenAsync, Point, sign, signAsync, utils, verify, verifyAsync, };

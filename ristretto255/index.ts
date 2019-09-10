/*! noble-ristretto255 - MIT License (c) Paul Miller (paulmillr.com) */
import { FieldElement } from "./field";
import { RistrettoPoint, BASE_POINT as B } from "./ristretto";
import {
  sha512,
  toBigInt,
  hexToBytes,
  fromBytesLE,
  numberToBytes,
  concatTypedArrays
} from "./utils";

// type PrivateKey = Uint8Array | string | bigint | number;
// type PublicKey = Uint8Array | string | RistrettoPoint;
// type Signature = Uint8Array | string | SignatureResult;
// type Bytes = Uint8Array | string;

// const ENCODING_LENGTH = 32;

export const P = FieldElement.P;
export const PRIME_ORDER = FieldElement.PRIME_ORDER;
export { RistrettoPoint, BASE_POINT } from "./ristretto";

// class SignatureResult {
//   constructor(public r: RistrettoPoint, public s: bigint) {}

//   static fromBytes(hex: Bytes) {
//     hex = typeof hex === "string" ? hexToBytes(hex) : hex;
//     const r = RistrettoPoint.fromBytes(hex.slice(0, 32));
//     const s = fromBytesLE(hex.slice(32));
//     return new SignatureResult(r, s);
//   }

//   toBytes() {
//     const sBytes = numberToBytes(this.s).reverse();
//     const rBytes = this.r.toBytes();
//     return concatTypedArrays(rBytes, sBytes);
//   }
// }

// function getPrivateBytes(privateKey: bigint) {
//   return sha512(numberToBytes(privateKey));
// }

// function encodePrivate(privateBytes: Uint8Array) {
//   const last = ENCODING_LENGTH - 1;
//   const head = privateBytes.slice(0, ENCODING_LENGTH);
//   head[0] &= 248;
//   head[last] &= 127;
//   head[last] |= 64;
//   return fromBytesLE(head);
// }

// function normalizeHash(hash: Bytes) {
//   return typeof hash === "string" ? hexToBytes(hash) : hash;
// }

// function normalizePublicKey(publicKey: PublicKey) {
//   if (publicKey instanceof RistrettoPoint) {
//     return publicKey;
//   }
//   publicKey = normalizeHash(publicKey);
//   return RistrettoPoint.fromBytes(publicKey);
// }

// function normalizeSignature(signature: Signature) {
//   if (signature instanceof SignatureResult) {
//     return signature;
//   }
//   signature = normalizeHash(signature);
//   return SignatureResult.fromBytes(signature);
// }

// async function hashNumber(...args: Uint8Array[]) {
//   const messageArray = concatTypedArrays(...args);
//   const hash = await sha512(messageArray);
//   const value = fromBytesLE(hash);
//   return FieldElement.mod(value, PRIME_ORDER);
// }

// export async function getPublicKey(privateKey: PrivateKey, shouldBeRaw = false) {
//   const multiplier = toBigInt(privateKey);
//   const privateBytes = await getPrivateBytes(multiplier);
//   const privateInt = encodePrivate(privateBytes);
//   const publicKey = exports.BASE_POINT.multiply(privateInt);
//   return shouldBeRaw ? publicKey : publicKey.toBytes();
// }

// export async function sign(message: Bytes, privateKey: PrivateKey) {
//   privateKey = toBigInt(privateKey);
//   message = normalizeHash(message);
//   const [publicKey, privateBytes] = await Promise.all([
//     getPublicKey(privateKey, true),
//     getPrivateBytes(privateKey)
//   ]);
//   const privatePrefix = privateBytes.slice(ENCODING_LENGTH);
//   const r = await hashNumber(privatePrefix, message);
//   const R = B.multiply(r);
//   const h = await hashNumber(R.toBytes(), publicKey.toBytes(), message);
//   const S = FieldElement.mod(r + h * encodePrivate(privateBytes), PRIME_ORDER);
//   const signature = new SignatureResult(R, S);
//   return signature.toBytes();
// }

// export async function verify(
//   signature: Signature,
//   message: Bytes,
//   publicKey: PublicKey
// ) {
//   message = normalizeHash(message);
//   publicKey = normalizePublicKey(publicKey);
//   signature = normalizeSignature(signature);
//   const h = await hashNumber(signature.r.toBytes(), publicKey.toBytes(), message);
//   const S = BASE_POINT.multiply(signature.s);
//   const R = signature.r.add(publicKey.multiply(h));
//   return S.equals(R);
// }

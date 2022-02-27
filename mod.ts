// prettier-ignore
import {
  getPublicKey, sign, verify, getSharedSecret, CURVE, curve25519, utils, ExtendedPoint, RistrettoPoint, Point, Signature
} from './ed25519.ts';

utils.randomBytes = (bytesLength = 32) => {
  return crypto.getRandomValues(new Uint8Array(bytesLength));
};

utils.sha512 = async (message: Uint8Array): Promise<Uint8Array> => {
  return new Uint8Array(await crypto.subtle.digest("SHA-512", message.buffer));
};
// prettier-ignore
export { getPublicKey, sign, verify, getSharedSecret, CURVE, curve25519, utils, ExtendedPoint, RistrettoPoint, Point, Signature };

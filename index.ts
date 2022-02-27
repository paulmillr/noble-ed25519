// prettier-ignore
import {
  getPublicKey, sign, verify, getSharedSecret, CURVE, curve25519, utils, ExtendedPoint, RistrettoPoint, Point, Signature,
} from "./ed25519";

// Uses built-in crypto module from node.js to generate randomness / hmac-sha256.
// In browser the line is automatically removed during build time: uses crypto.subtle instead.
import nodeCrypto from "crypto";

// Global symbol available in browsers only. Ensure we do not depend on @types/dom
declare const self: Record<string, any> | undefined;
const crypto: { node?: any; web?: any } = {
  node: nodeCrypto,
  web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
};

if (crypto.web) {
  utils.randomBytes = (bytesLength = 32) => {
    return crypto.web.getRandomValues(new Uint8Array(bytesLength));
  };
  
  utils.sha512 = async (message: Uint8Array): Promise<Uint8Array> => {
    return new Uint8Array(await crypto.web.subtle.digest("SHA-512", message.buffer));
  };
} else if (crypto.node) {
  utils.randomBytes = (bytesLength = 32) => {
    return new Uint8Array(crypto.node.randomBytes(bytesLength).buffer);
  };
  
  utils.sha512 = async (message: Uint8Array): Promise<Uint8Array> => {
    return Uint8Array.from(crypto.node.createHash("sha512").update(message).digest());
  };
}

// prettier-ignore
export { getPublicKey, sign, verify, getSharedSecret, CURVE, curve25519, utils, ExtendedPoint, RistrettoPoint, Point, Signature };

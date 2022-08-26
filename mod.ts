// prettier-ignore
import {
  CURVE, ExtendedPoint, Point, RistrettoPoint,
  getPublicKey, sign, verify, sync, utils
} from './index.ts';
import { crypto } from 'https://deno.land/std@0.153.0/crypto/mod.ts';

utils.sha512 = async (...msgs: Uint8Array[]): Promise<Uint8Array> => {
  return new Uint8Array(await crypto.subtle.digest('SHA-512', utils.concatBytes(...msgs)));
};
utils.sha512Sync = (...msgs: Uint8Array[]): Uint8Array => {
  return new Uint8Array(crypto.subtle.digestSync('SHA-512', utils.concatBytes(...msgs)));
};

// prettier-ignore
export {
  CURVE, ExtendedPoint, Point, RistrettoPoint,
  getPublicKey, sign, verify, sync, utils
};

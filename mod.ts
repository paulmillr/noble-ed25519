// prettier-ignore
import {
  getPublicKey, sign, verify, utils, CURVE, Point, ExtendedPoint, RistrettoPoint
} from './index.ts';
import { crypto } from 'https://deno.land/std@0.125.0/crypto/mod.ts';

utils.sha512 = async (message: Uint8Array): Promise<Uint8Array> => {
  return new Uint8Array(await crypto.subtle.digest('SHA-512', message));
};

export { getPublicKey, sign, verify, utils, CURVE, Point, ExtendedPoint, RistrettoPoint };

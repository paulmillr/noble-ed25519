import { getPublicKey, sign, verify, utils, CURVE, Point, ExtendedPoint } from './index.ts';
import { Sha512 } from 'https://deno.land/std@0.119.0/hash/sha512.ts';

utils.sha512 = async (message: Uint8Array): Promise<Uint8Array> => {
  return new Uint8Array(new Sha512().update(message).arrayBuffer());
};

export { getPublicKey, sign, verify, utils, CURVE, Point, ExtendedPoint };

import { getPublicKey, sign, verify, utils, CURVE, Point, ExtendedPoint } from './index.ts';
import { SHA512 } from 'https://denopkg.com/chiefbiiko/sha512/mod.ts';

utils.sha512 = async (message: Uint8Array): Promise<Uint8Array> => {
  return new SHA512().update(message).digest() as Uint8Array;
};

export { getPublicKey, sign, verify, utils, CURVE, Point, ExtendedPoint };

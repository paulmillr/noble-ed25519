/*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) */

import { ed25519, RistrettoPoint, x25519 } from '@noble/curves/ed25519';
import * as genUtils from '@noble/curves/abstract/utils';
import { PointType } from '@noble/curves/abstract/edwards';
import { randomBytes } from '@noble/hashes/utils';

const { getPublicKey, sign, verify, Point, Signature, utils: edUtils, CURVE } = ed25519;
export { getPublicKey, sign, verify, Point, Signature, CURVE, RistrettoPoint };

export const utils = Object.assign(
  {
    sha512(data: Uint8Array) {
      return ed25519.CURVE.hash(data);
    },
    sha512Sync: (data: Uint8Array) => {
      return ed25519.CURVE.hash(data);
    },
    precompute(a: number) {},
  },
  edUtils,
  genUtils,
  { randomBytes }
);

export const sync = {
  getPublicKey,
  sign,
  verify,
};

export function pointToX25519(point: PointType): Uint8Array {
  const { y } = point;
  const u = CURVE.Fp.div(1n + y, 1n - y);
  return utils.numberToBytesLE(u, 32);
}

type Hex = Uint8Array | string;
export function getSharedSecret(privateKey: Hex, publicKey: Hex): Uint8Array {
  const { head } = utils.getExtendedPublicKey(privateKey);
  const u = pointToX25519(Point.fromHex(publicKey));
  return curve25519.scalarMult(head, u);
}

export const curve25519 = {
  getPublicKey: x25519.scalarMultBase,
  scalarMult: x25519.scalarMult,
  scalarMultBase: x25519.scalarMultBase,
  BASE_POINT_U: x25519.Gu,
};

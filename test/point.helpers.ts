import * as ed25519 from '../index.ts';
import './ed25519.helpers.ts';
import { bytesToHex as hex, hexToBytes, invert, mod } from './utils.helpers.ts';

// prettier-ignore
export const CURVES = {
  ed25519,
};

export function getOtherCurve(_currCurveName) {
  class Point {
    constructor() {}
    add() {
      throw new Error('1');
    }
    subtract() {
      throw new Error('1');
    }
    multiply() {
      throw new Error('1');
    }
    multiplyUnsafe() {}
    static fromAffine() {
      throw new Error('1');
    }
  }
  return { Point };
}

export const pippenger = undefined;
export const precomputeMSMUnsafe = undefined;
export const wNAF = undefined;
export { hex, hexToBytes, invert, mod };

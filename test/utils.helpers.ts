import * as items from '../index.ts';

type Etc = {
  bytesToHex: (value: Uint8Array) => string;
  concatBytes: (...values: Uint8Array[]) => Uint8Array;
  hexToBytes: (value: string) => Uint8Array;
  mod: (a: bigint, b: bigint) => bigint;
  invert: (value: bigint, modulo: bigint) => bigint;
  abytes?: (value: unknown, length?: number, title?: string) => Uint8Array;
  copyBytes?: (value: Uint8Array) => Uint8Array;
  equalBytes?: (a: Uint8Array, b: Uint8Array) => boolean;
  asciiToBytes?: (value: string) => Uint8Array;
  hexToNumber?: (value: string) => bigint;
  numberToHexUnpadded?: (value: number | bigint) => string;
  numberToBytesBE?: (value: number | bigint, length: number) => Uint8Array;
  numberToBytesLE?: (value: number | bigint, length: number) => Uint8Array;
  numberToVarBytesBE?: (value: number | bigint) => Uint8Array;
  aInRange?: (title: string, value: bigint, min: bigint, max: bigint) => void;
  abool?: (value: boolean) => boolean;
  asafenumber?: (value: number) => void;
  validateObject?: (value: unknown, validators: Record<string, string>) => void;
  bitSet?: (value: bigint, bit: number, enable: boolean) => bigint;
  bitLen?: (value: bigint) => number;
  createHmacDrbg?: (
    hashLen: number,
    qByteLen: number,
    hmacFn: (key: Uint8Array, msg: Uint8Array) => Uint8Array
  ) => (seed: Uint8Array, pred: () => bigint) => bigint;
};
type Ed = {
  Point: { BASE: { multiply: (value: bigint) => unknown } };
  utils: { randomSecretKey: (seed?: Uint8Array) => Uint8Array };
};
type Secp = {
  getPublicKey: (secretKey: Uint8Array, isCompressed?: boolean) => Uint8Array;
  utils: { randomSecretKey: (seed?: Uint8Array) => Uint8Array };
};

export const etc: Etc = items.etc as Etc;
export const { bytesToHex, concatBytes, hexToBytes, mod, invert } = etc;
export const extra = etc;
export const ed: Ed | undefined = items as unknown as Ed;
export const secp: Secp | undefined = undefined;

export let sha512: (a: Uint8Array) => Promise<Uint8Array>;

if (typeof window == "object" && "crypto" in window) {
  sha512 = async (message: Uint8Array) => {
    const buffer = await window.crypto.subtle.digest("SHA-512", message.buffer);
    return new Uint8Array(buffer);
  };
} else if (typeof process === "object" && "node" in process.versions) {
  const { createHash } = require("crypto");
  sha512 = async (message: Uint8Array) => {
    const hash = createHash("sha512");
    hash.update(message);
    return Uint8Array.from(hash.digest());
  };
} else {
  throw new Error("The environment doesn't have sha512 function");
}

function fromHexBE(hex: string) {
  return BigInt(`0x${hex}`);
}

function fromBytesBE(bytes: string | Uint8Array) {
  if (typeof bytes === "string") {
    return fromHexBE(bytes);
  }
  let value = 0n;
  for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
    value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
  }
  return value;
}

export function fromBytesLE(bytes: Uint8Array) {
  let value = 0n;
  for (let i = 0; i < bytes.length; i++) {
    value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(i));
  }
  return value;
}

export function hexToBytes(hash: string) {
  hash = hash.length & 1 ? `0${hash}` : hash;
  const len = hash.length;
  const result = new Uint8Array(len / 2);
  for (let i = 0, j = 0; i < len - 1; i += 2, j++) {
    result[j] = parseInt(hash[i] + hash[i + 1], 16);
  }
  return result;
}

export function toBigInt(num: string | Uint8Array | bigint | number) {
  if (typeof num === "string") {
    return fromHexBE(num);
  }
  if (typeof num === "number") {
    return BigInt(num);
  }
  if (num instanceof Uint8Array) {
    return fromBytesBE(num);
  }
  return num;
}

export function isBytesEquals(b1: Uint8Array, b2: Uint8Array) {
  if (b1.length !== b2.length) {
    return false;
  }
  for (let i = 0; i < b1.length; i++) {
    if (b1[i] !== b2[i]) {
      return false;
    }
  }
  return true;
}

export function numberToBytes(num: bigint) {
  let hex = num.toString(16);
  hex = hex.length & 1 ? `0${hex}` : hex;
  const len = hex.length / 2;
  const u8 = new Uint8Array(len);
  for (let j = 0, i = 0; i < hex.length; i += 2, j++) {
    u8[j] = parseInt(hex[i] + hex[i + 1], 16);
  }
  return u8;
}

export function concatTypedArrays(...args: Uint8Array[]) {
  const result = new Uint8Array(args.reduce((a, arr) => a + arr.length, 0));
  for (let i = 0, pad = 0; i < args.length; i++) {
    const arr = args[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

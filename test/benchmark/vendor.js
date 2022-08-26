const {run, mark} = require('micro-bmark');
const tweetnacl = require('tweetnacl');
const ristretto255 = require('ristretto255');
const sod = require('sodium-native');

run(async () => {
  const priv = new Uint8Array(32).fill(1);
  const privLong = new Uint8Array(64).fill(2);
  const msg = new Uint8Array(64);
  let pub;
  console.log(sod.crypto_sign_BYTES);
  console.log('tweetnacl@1.0.3')
  await mark('getPublicKey', 2000, () => tweetnacl.scalarMult.base(priv));
  await mark('sign', 700, () => tweetnacl.sign(msg, privLong));
  console.log('ristretto255@0.1.2')
  await mark('getPublicKey', 700, () => ristretto255.scalarMultBase(priv));
  console.log('sodium-native')
  await mark('sign', 100000, () => sod.crypto_sign(new Uint8Array(128), msg, privLong))
});
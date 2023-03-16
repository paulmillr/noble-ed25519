import {run, mark} from 'micro-bmark';
import tweetnacl from 'tweetnacl';
import ristretto255 from 'ristretto255';
import sod from 'sodium-native';

run(async () => {
  const priv = new Uint8Array(32).fill(1);
  const privLong = new Uint8Array(64).fill(2);
  const msg = new Uint8Array(64);
  let pub;
  await mark('tweetnacl@1.0.3 getPublicKey', 2000, () => tweetnacl.scalarMult.base(priv));
  await mark('tweetnacl@1.0.3 sign', 700, () => tweetnacl.sign(msg, privLong));
  await mark('ristretto255@0.1.2 getPublicKey', 700, () => ristretto255.scalarMultBase(priv));
  await mark('sodium-native#sign', 100000, () => sod.crypto_sign(new Uint8Array(128), msg, privLong))
});
const {run, mark, logMem} = require('micro-bmark');
let ed = require('.');

run(async () => {
  // warm-up
  await mark(() => {
    ed.utils.precompute();
  });

  logMem();
  console.log();

  function toBytes(numOrStr) {
    let hex = typeof numOrStr === 'string' ? numOrStr : numOrStr.toString(16);
    hex = hex.length & 1 ? `0${hex}` : hex;
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
      let j = i * 2;
      array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
  }

  const priv1 = toBytes(2n);
  let pubHex;
  await mark('getPublicKey 1 bit', 1000, async () => {
    pubHex = await ed.getPublicKey(priv1);
  });

  const priv2 = toBytes(0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60n);
  await mark('getPublicKey', 1000, async () => {
    pubHex = await ed.getPublicKey(priv2);
  });

  const msg = toBytes('deadbeefdeadbeefdeadbeefdeadbeefdeadbeef');
  let sigHex;
  await mark('sign', 1000, async () => {
    sigHex = await ed.sign(msg, priv2);
  });

  await mark('verify', 1000, async () => {
    const verified = await ed.verify(sigHex, msg, pubHex);
  });

  const sig = ed.SignResult.fromHex(sigHex);
  const pub = ed.Point.fromHex(pubHex);
  await mark('verifyBatch', 1000, async () => {
    const verified = await ed.verify(sig, msg, pub);
  });

  console.log();
  logMem();
});

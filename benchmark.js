const {run, mark, logMem} = require('micro-bmark');
let ed = require('.');

run(async () => {
  // warm-up
  let pubHex;
  await mark(() => {
    ed.utils.precompute();
  });

  logMem();
  console.log();


  await mark('getPublicKey 1 bit', 1000, async () => {
    pubHex = await ed.getPublicKey(2n);
  });

  // console.profile('cpu');
  const priv = 0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60n;
  await mark('getPublicKey', 1000, async () => {
    pubHex = await ed.getPublicKey(priv);
  });

  const msgHex = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
  let sigHex;
  await mark('sign', 1000, async () => {
    sigHex = await ed.sign(msgHex, priv);
  });

  const sig = ed.SignResult.fromHex(sigHex);
  const pub = ed.Point.fromHex(pubHex);
  // console.profile('bench');
  await mark('verify', 1000, async () => {
    const verified = await ed.verify(sigHex, msgHex, pubHex);
  });
  await mark('verifyBatch', 1000, async () => {
    const verified = await ed.verify(sig, msgHex, pub);
  });
  // console.profileEnd('bench'); debugger;

  console.log();
  logMem();
});

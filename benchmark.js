const {run, mark, logMem} = require('micro-bmark');
let ed = require('.');

run(async () => {
  // warm-up
  let pub;
  await mark(() => {
    ed.utils.precompute();
  });

  logMem();
  console.log();

  await mark('getPublicKey 1 bit', 1000, async () => {
    pub = await ed.getPublicKey(2n);
  });

  // console.profile('cpu');
  const priv = 0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60n;
  await mark('getPublicKey', 1000, async () => {
    pub = await ed.getPublicKey(priv);
  });

  const message = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
  let signature;
  await mark('sign', 1000, async () => {
    signature = await ed.sign(message, priv);
  });

  await mark('verify', 1000, async () => {
    const verified = await ed.verify(signature, message, pub);
    // console.log({verified});
  });

  console.log();
  logMem();
});

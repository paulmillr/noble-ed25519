const s = require('.');

(async () => {
  const priv = 0xdeadbeefdeadbeef;
  const msg = 'deadbeefdeadbeefdeadbeefdeadbeef';
  const pub = await s.getPublicKey(priv);
  const sig = await s.sign(msg, priv);
  console.profile('verify');
  await s.verify(sig, msg, pub);
  console.profileEnd('verify');
  debugger;
})();
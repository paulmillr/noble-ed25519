const ed = require('.');

function logMem(i) {
  const vals = Object.entries(process.memoryUsage()).map(([k, v]) => {
    return `${k}=${(`${(v / 1e6).toFixed(1)}M`).padEnd(7)}`;
  });
  console.log(String(i).padStart(6), ...vals);
}

async function bench(name, counts, priv, pub) {
  const label = `${name} x${counts}`;
  const start = Date.now();
  for (let i = 0; i < counts; i++) {
    await ed.getPublicKey('beef');
  }
  console.log(`${label}: ${Date.now() - start}`);
}

(async () => {
  logMem('start');

  const priv = 'beef';
  const expected = '096596f308a288d1f8a8bcaca202eb6dd6da707e60e64427a2baa568eb2e31c4';
  let start = Date.now();
  let actual;
  function time() {
    let now = Date.now();
    console.log(now - start, {actual, expected});
    start = now;
  }

  ed.utils.precompute();
  time();
  actual = await ed.getPublicKey(priv);
  time();
  // actual = await ed.getPublicKey(priv);
  // time();

  logMem('end');
})()

// // console.profile('cpu');
// const priv = 2n ** 255n + 12341n;
// bench('getPublicKey 256 bit', 1, async () => {
//   pub = await ed.getPublicKey(priv);
// });

// let custom = ed.Point.fromHex(pub);
// bench('multiply custom point', 1, () => {
//   pub = custom.multiply(0x0123456789abcdef012789abcdef0123456789abcdef0123456789abcdefn);
// });

// ed.getPublicKey('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');

// console.profileEnd('cpu');

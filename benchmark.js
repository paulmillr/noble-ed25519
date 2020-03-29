let ed = require('.');

function time() {
  return process.hrtime.bigint();
}

function logMem() {
  const vals = Object.entries(process.memoryUsage()).map(([k, v]) => {
    return `${k}=${`${(v / 1e6).toFixed(1)}M`.padEnd(7)}`;
  });
  console.log('RAM:', ...vals);
}

async function bench(label, samples, callback) {
  let initial = false;
  if (typeof label === 'function' && !samples && !callback) {
    callback = label;
    samples = 1;
    label = 'Initialized in';
    initial = true;
  }
  const [μs, ms, sec] = [1000n, 1000000n, 1000000000n];
  const start = time();
  for (let i = 0; i < samples; i++) {
    let val = callback();
    if (val instanceof Promise) await val;
  }
  const end = time();
  const total = end - start;
  const perItem = total / BigInt(samples);

  let perItemStr = perItem.toString();
  let symbol = 'ns';
  if (perItem > μs) {
    symbol = 'μs';
    perItemStr = (perItem / μs).toString();
  }
  if (perItem > ms) {
    symbol = 'ms';
    perItemStr = (perItem / ms).toString();
  }

  const perSec = (sec / perItem).toString();
  let str = `${label} `;
  if (!initial) {
    str += `x ${perSec} ops/sec, ${perItemStr}${symbol} / op, ${samples} samples`;
  } else {
    str += `${perItemStr}${symbol}`;
  }
  console.log(str);
}

(async () => {
  // warm-up
  let pub;
  console.log('Benchmarking...\n');
  await bench(() => {

    ed.utils.precompute();
  });

  logMem('start');
  console.log();

  await bench('getPublicKey 1 bit', 1000, async () => {
    pub = await ed.getPublicKey(2n);
  });

  // console.profile('cpu');
  const priv = 0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60n;
  await bench('getPublicKey 256 bit', 1000, async () => {
    pub = await ed.getPublicKey(priv);
  });

  const message = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
  let signature;
  await bench('sign', 1000, async () => {
    signature = await ed.sign(message, priv);
  });

  await bench('verify', 1000, async () => {
    const verified = await ed.verify(signature, message, pub);
  });

  console.log();
  logMem();
})();

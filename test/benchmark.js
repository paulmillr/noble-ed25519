const {run, mark, logMem} = require('micro-bmark');
const {sha512} = require('@noble/hashes/sha512')
let ed = require('..');

run(async () => {
  // warm-up
  await mark(() => {
    ed.utils.precompute();
  });

  logMem();
  console.log();

  function toBytes(numOrStr) {
    let hex = typeof numOrStr === 'string' ? numOrStr : numOrStr.toString(16);
    hex = hex.padStart(64, '0');
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
      let j = i * 2;
      array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
  }

  const priv1bit = toBytes(2n);
  const priv = toBytes(0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60n);
  const msg = toBytes('deadbeefdeadbeefdeadbeefdeadbeefdeadbeef');

  let pubHex, sigHex;
  await mark('getPublicKey 1 bit', 6000, async () => {
    pubHex = await ed.getPublicKey(priv1bit);
  });

  await mark('getPublicKey(utils.randomPrivateKey())', 6000, async () => {
    pubHex = await ed.getPublicKey(ed.utils.randomPrivateKey());
  });

  await mark('sign', 4000, async () => {
    sigHex = await ed.sign(msg, priv);
  });
  const sigInst = ed.Signature.fromHex(sigHex);
  const pubInst = ed.Point.fromHex(pubHex);

  await mark('verify', 800, async () => {
    return await ed.verify(sigHex, msg, pubHex);
  });

  await mark('verify (no decompression)', 950, async () => {
    return await ed.verify(sigInst, msg, pubInst);
  });
  await mark('Point.fromHex decompression', 13000, () => {
    ed.Point.fromHex(pubHex);
  });

  const encodingsOfSmallMultiples = [
    // This is the identity point
    '0000000000000000000000000000000000000000000000000000000000000000',
    // This is the basepoint
    'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76',
    // These are small multiples of the basepoint
    '6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919',
    '94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259',
    'da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57',
    'e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e',
    'f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403',
    '44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d',
    '903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c',
    '02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031',
    '20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f',
    'bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42',
    'e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460',
    'aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f',
    '46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e',
    'e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e'
  ].map(n => ed.utils.hexToBytes(n));
  const hash = new Uint8Array([
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
  ])
  await mark('ristretto255#hashToCurve', 6000, () => {
    ed.RistrettoPoint.hashToCurve(hash);
  });
  await mark('ristretto255 round', 6000, () => {
    ed.RistrettoPoint.fromHex(encodingsOfSmallMultiples[2]).toHex();
  });
  mark('curve25519.scalarMultBase', 1200, () => {
    ed.curve25519.scalarMultBase('aeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef');
  });
  await mark('ed25519.getSharedSecret', 1000, async () => {
    await ed.getSharedSecret(0x12345, 'aeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef');
  });

  ed.utils.sha512Sync = (...m) => sha512(ed.utils.concatBytes(...m));
  await mark('sync.getPublicKey()', 6000, () => sync.getPublicKey(ed.utils.randomPrivateKey()));
  await mark('sync.sign', 4000, () => sync.sign(msg, priv));
  await mark('sync.verify', 800, () => sync.verify(sigHex, msg, pubHex));
  await mark('sync.verify (no decompression)', 950, () => sync.verify(sigInst, msg, pubInst));

  logMem();
});

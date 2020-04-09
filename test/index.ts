import * as fc from 'fast-check';
import * as ed25519 from '../';
import { readFileSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';

const PRIVATE_KEY = toBytes('a665a45920422f9d417e4867ef');
// const MESSAGE = ripemd160(new Uint8Array([97, 98, 99, 100, 101, 102, 103]));
const MESSAGE = new Uint8Array([
  135,
  79,
  153,
  96,
  197,
  210,
  183,
  169,
  181,
  250,
  211,
  131,
  225,
  186,
  68,
  113,
  158,
  187,
  116,
  58
]);
// const WRONG_MESSAGE = ripemd160(new Uint8Array([98, 99, 100, 101, 102, 103]));
const WRONG_MESSAGE = new Uint8Array([
  88,
  157,
  140,
  127,
  29,
  160,
  162,
  75,
  192,
  123,
  115,
  129,
  173,
  72,
  177,
  207,
  194,
  17,
  175,
  28
]);

function toBytes(numOrStr: string | bigint | number): Uint8Array {
  let hex = typeof numOrStr === 'string' ? numOrStr : numOrStr.toString(16).padStart(64, '0');
  hex = hex.length & 1 ? `0${hex}` : hex;
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    let j = i * 2;
    array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
  }
  return array;
}

function arrayToHex(uint8a: Uint8Array): string {
  return Array.from(uint8a)
    .map(c => c.toString(16).padStart(2, '0'))
    .join('');
}

describe('ed25519', () => {
  beforeAll(() => {
    ed25519.utils.precompute(8);
  });
  it('should verify just signed message', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.hexaString(1, 32),
        fc.bigInt(2n, ed25519.CURVE.n),
        async (message: string, privateKey: bigint) => {
          const publicKey = await ed25519.getPublicKey(privateKey);
          const signature = await ed25519.sign(toBytes(message), toBytes(privateKey));
          expect(publicKey.length).toBe(32);
          expect(signature.length).toBe(64);
          expect(await ed25519.verify(signature, message, publicKey)).toBe(true);
        }
      ),
      { numRuns: 5 }
    );
  });
  it('should not verify sign with wrong message', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.integer(0x00, 0xff)),
        fc.array(fc.integer(0x00, 0xff)),
        fc.bigInt(1n, ed25519.CURVE.n),
        async (bytes, wrongBytes, privateKey) => {
          const message = new Uint8Array(bytes);
          const wrongMessage = new Uint8Array(wrongBytes);
          const publicKey = await ed25519.getPublicKey(privateKey);
          const signature = await ed25519.sign(message, toBytes(privateKey));
          expect(await ed25519.verify(signature, wrongMessage, publicKey)).toBe(
            bytes.toString() === wrongBytes.toString()
          );
        }
      ),
      { numRuns: 5 }
    );
  });
  describe('verify()', () => {
    it('should sign and verify', async () => {
      const publicKey = await ed25519.getPublicKey(PRIVATE_KEY);
      const signature = await ed25519.sign(MESSAGE, PRIVATE_KEY);
      expect(await ed25519.verify(signature, MESSAGE, publicKey)).toBe(true);
    });
    it('should not verify signature with wrong public key', async () => {
      const publicKey = await ed25519.getPublicKey(12);
      const signature = await ed25519.sign(MESSAGE, PRIVATE_KEY);
      expect(await ed25519.verify(signature, MESSAGE, publicKey)).toBe(false);
    });
    it('should not verify signature with wrong hash', async () => {
      const publicKey = await ed25519.getPublicKey(PRIVATE_KEY);
      const signature = await ed25519.sign(MESSAGE, PRIVATE_KEY);
      expect(await ed25519.verify(signature, WRONG_MESSAGE, publicKey)).toBe(false);
    });
  });
  describe('BASE_POINT.multiply()', () => {
    // https://xmr.llcoins.net/addresstests.html
    it('should create right publicKey without SHA-512 hashing TEST 1', () => {
      const publicKey = ed25519.Point.BASE.multiply(
        0x90af56259a4b6bfbc4337980d5d75fbe3c074630368ff3804d33028e5dbfa77n
      );
      expect(publicKey.toHex()).toBe(
        '0f3b913371411b27e646b537e888f685bf929ea7aab93c950ed84433f064480d'
      );
    });
    it('should create right publicKey without SHA-512 hashing TEST 2', () => {
      const publicKey = ed25519.Point.BASE.multiply(
        0x364e8711a60780382a5d57b061c126f039940f28a9e91fe039d4d3094d8b88n
      );
      expect(publicKey.toHex()).toBe(
        'ad545340b58610f0cd62f17d55af1ab11ecde9c084d5476865ddb4dbda015349'
      );
    });
    it('should create right publicKey without SHA-512 hashing TEST 3', () => {
      const publicKey = ed25519.Point.BASE.multiply(
        0xb9bf90ff3abec042752cac3a07a62f0c16cfb9d32a3fc2305d676ec2d86e941n
      );
      expect(publicKey.toHex()).toBe(
        'e097c4415fe85724d522b2e449e8fd78dd40d20097bdc9ae36fe8ec6fe12cb8c'
      );
    });
    it('should create right publicKey without SHA-512 hashing TEST 4', () => {
      const publicKey = ed25519.Point.BASE.multiply(
        0x69d896f02d79524c9878e080308180e2859d07f9f54454e0800e8db0847a46en
      );
      expect(publicKey.toHex()).toBe(
        'f12cb7c43b59971395926f278ce7c2eaded9444fbce62ca717564cb508a0db1d'
      );
    });
  });

  describe('Point#toX25519()', () => {
    it('should convert base point to montgomery', async () => {
      expect(ed25519.Point.BASE.toX25519()).toBe(9n);
    });

    it('should convert TEST 1 to montgomery', async () => {
      const priv = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';
      const pub = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';
      const montgomery = '478dd307cdfb042d80d03e0f55227e4d982bedd1696ba700fc8ab894c504c725';

      const point = ed25519.Point.fromHex(pub);
      expect(point.toX25519().toString(16)).toBe(montgomery);
    });

    it('should convert TEST 2 to montgomery', async () => {
      const priv = '0c';
      const pub = '1262bc6d5408a3c4e025aa0c15e64f69197cdb38911be5ad344a949779df3da6';
      const montgomery = '31c3ec9e22ce8ffd4fa9dfa1a698604b4de4921be0e09ca93f96c635bb8de1db';

      const publicKey = await ed25519.getPublicKey(priv);
      expect(publicKey).toBe(pub);
      const point = ed25519.Point.fromHex(publicKey);
      expect(point.toX25519().toString(16)).toBe(montgomery);
    });

    it('should convert TEST 3 to montgomery', async () => {
      const priv = '27';
      const pub = 'd7e1ba312ceaf90c89566a9a7861316522a60edea4c2157eabf3d273169eac13';
      const montgomery = '48d70b86a448c72a4b3960d399102d9ef401092fcbbcda8e69bc230bc73bb9d2';

      const publicKey = await ed25519.getPublicKey(priv);
      expect(publicKey).toBe(pub);
      const point = ed25519.Point.fromHex(publicKey);
      expect(point.toX25519().toString(16)).toBe(montgomery);
    });
  });
});

// https://ed25519.cr.yp.to/python/sign.py
// https://ed25519.cr.yp.to/python/sign.input
describe('ed25519 official vectors', () => {
  const data = readFileSync(join(__dirname, 'vectors.txt'), 'utf-8');
  const vectors = data
    .trim()
    .split('\n')
    .map(line => line.split(':'));

  it('should match 1024 official vectors', async () => {
    for (let i = 0; i < vectors.length; i++) {
      const vector = vectors[i];
      // Extract.
      const priv = vector[0].slice(0, 64);
      const expectedPub = vector[1];
      const msg = vector[2];
      const expectedSignature = vector[3].slice(0, 128);

      // Calculate
      const pub = await ed25519.getPublicKey(priv);
      const signature = await ed25519.sign(msg, priv);
      // console.log('vector', i);
      expect(pub).toBe(expectedPub);
      expect(signature).toBe(expectedSignature);
    }
  });
});

// https://tools.ietf.org/html/rfc8032#section-7
describe('rfc8032 vectors', () => {
  it('should create right signature for 0x9d and empty string', async () => {
    const privateKey = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
    const publicKey = await ed25519.getPublicKey(privateKey);
    const message = '';
    const signature = await ed25519.sign(message, privateKey);
    expect(publicKey).toBe('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    expect(signature).toBe(
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
    );
  });
  it('should create right signature for 0x4c and 72', async () => {
    const privateKey = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';
    const publicKey = await ed25519.getPublicKey(privateKey);
    const message = '72';
    const signature = await ed25519.sign(message, privateKey);
    expect(publicKey).toBe('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c');
    expect(signature).toBe(
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'
    );
  });
  it('should create right signature for 0x00 and 5a', async () => {
    const privateKey = '002fdd1f7641793ab064bb7aa848f762e7ec6e332ffc26eeacda141ae33b1783';
    const publicKey = await ed25519.getPublicKey(privateKey);
    const message =
      '5ac1dfc324f43e6cb79a87ab0470fa857b51fb944982e19074ca44b1e40082c1d07b92efa7ea55ad42b7c027e0b9e33756d95a2c1796a7c2066811dc41858377d4b835c1688d638884cd2ad8970b74c1a54aadd27064163928a77988b24403aa85af82ceab6b728e554761af7175aeb99215b7421e4474c04d213e01ff03e3529b11077cdf28964b8c49c5649e3a46fa0a09dcd59dcad58b9b922a83210acd5e65065531400234f5e40cddcf9804968e3e9ac6f5c44af65001e158067fc3a660502d13fa8874fa93332138d9606bc41b4cee7edc39d753dae12a873941bb357f7e92a4498847d6605456cb8c0b425a47d7d3ca37e54e903a41e6450a35ebe5237c6f0c1bbbc1fd71fb7cd893d189850295c199b7d88af26bc8548975fda1099ffefee42a52f3428ddff35e0173d3339562507ac5d2c45bbd2c19cfe89b';
    const signature = await ed25519.sign(message, privateKey);
    expect(publicKey).toBe('77d1d8ebacd13f4e2f8a40e28c4a63bc9ce3bfb69716334bcb28a33eb134086c');
    expect(signature).toBe(
      '0df3aa0d0999ad3dc580378f52d152700d5b3b057f56a66f92112e441e1cb9123c66f18712c87efe22d2573777296241216904d7cdd7d5ea433928bd2872fa0c'
    );
  });
  it('should create right signature for 0xf5 and long msg', async () => {
    const privateKey = 'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5';
    const publicKey = await ed25519.getPublicKey(privateKey);
    const message =
      '08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0';
    const signature = await ed25519.sign(message, privateKey);
    expect(publicKey).toBe('278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e');
    expect(signature).toBe(
      '0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03'
    );
  });
});

describe('ristretto255', () => {
  const {ExtendedPoint} = ed25519;
  async function sha512(message: Uint8Array) {
    const hash = createHash('sha512');
    hash.update(message);
    return Uint8Array.from(hash.digest());
  }

  function arrayToHex(bytes: Uint8Array) {
    return Array.from(bytes)
      .map(a => a.toString(16).padStart(2, '0'))
      .join('');
  }

  function hexToArray(hash: string) {
    hash = hash.length & 1 ? `0${hash}` : hash;
    const len = hash.length;
    const result = new Uint8Array(len / 2);
    for (let i = 0, j = 0; i < len - 1; i += 2, j++) {
      result[j] = parseInt(hash[i] + hash[i + 1], 16);
    }
    return result;
  }

  const PRIVATE_KEY = 0xa665a45920422f9d417e4867efn;
  // const MESSAGE = ripemd160(new Uint8Array([97, 98, 99, 100, 101, 102, 103]));
  const MESSAGE = new Uint8Array([
    135,
    79,
    153,
    96,
    197,
    210,
    183,
    169,
    181,
    250,
    211,
    131,
    225,
    186,
    68,
    113,
    158,
    187,
    116,
    58
  ]);
  // const WRONG_MESSAGE = ripemd160(new Uint8Array([98, 99, 100, 101, 102, 103]));
  const WRONG_MESSAGE = new Uint8Array([
    88,
    157,
    140,
    127,
    29,
    160,
    162,
    75,
    192,
    123,
    115,
    129,
    173,
    72,
    177,
    207,
    194,
    17,
    175,
    28
  ]);
  // it("should verify just signed message", async () => {
  //   await fc.assert(fc.asyncProperty(
  //     fc.hexa(),
  //     fc.bigInt(2n, ristretto25519.PRIME_ORDER),
  //     async (message, privateKey) => {
  //       const publicKey = await ristretto25519.getPublicKey(privateKey);
  //       const signature = await ristretto25519.sign(message, privateKey);
  //       expect(publicKey.length).toBe(32);
  //       expect(signature.length).toBe(64);
  //       expect(await ristretto25519.verify(signature, message, publicKey)).toBe(true);
  //     }),
  //    { numRuns: 1 }
  //   );
  // });
  // it("should not verify sign with wrong message", async () => {
  //   await fc.assert(fc.asyncProperty(
  //     fc.array(fc.integer(0x00, 0xff)),
  //     fc.array(fc.integer(0x00, 0xff)),
  //     fc.bigInt(2n, ristretto25519.PRIME_ORDER),
  //     async (bytes, wrongBytes, privateKey) => {
  //       const message = new Uint8Array(bytes);
  //       const wrongMessage = new Uint8Array(wrongBytes);
  //       const publicKey = await ristretto25519.getPublicKey(privateKey);
  //       const signature = await ristretto25519.sign(message, privateKey);
  //       expect(await ristretto25519.verify(signature, wrongMessage, publicKey)).toBe(
  //         bytes.toString() === wrongBytes.toString()
  //       );
  //     }),
  //    { numRuns: 1 }
  //   );
  // });
  // it("should sign and verify", async () => {
  //   const publicKey = await ristretto25519.getPublicKey(PRIVATE_KEY);
  //   const signature = await ristretto25519.sign(MESSAGE, PRIVATE_KEY);
  //   expect(await ristretto25519.verify(signature, MESSAGE, publicKey)).toBe(true);
  // });
  // it("should not verify signature with wrong public key", async () => {
  //   const publicKey = await ristretto25519.getPublicKey(12);
  //   const signature = await ristretto25519.sign(MESSAGE, PRIVATE_KEY);
  //   expect(await ristretto25519.verify(signature, MESSAGE, publicKey)).toBe(false);
  // });
  // it("should not verify signature with wrong hash", async () => {
  //   const publicKey = await ristretto25519.getPublicKey(PRIVATE_KEY);
  //   const signature = await ristretto25519.sign(MESSAGE, PRIVATE_KEY);
  //   expect(await ristretto25519.verify(signature, WRONG_MESSAGE, publicKey)).toBe(false);
  // });
  it('should follow the byte encodings of small multiples', () => {
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
    ];
    let B = ExtendedPoint.BASE;
    let P = ExtendedPoint.ZERO;
    for (const encoded of encodingsOfSmallMultiples) {
      expect(arrayToHex(P.toRistrettoBytes())).toBe(encoded);
      expect(arrayToHex(ExtendedPoint.fromRistrettoBytes(hexToArray(encoded)).toRistrettoBytes())).toBe(encoded);
      P = P.add(B);
    }
  });
  it('should not convert bad bytes encoding', () => {
    const badEncodings = [
      // These are all bad because they're non-canonical field encodings.
      '00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      'f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      // These are all bad because they're negative field elements.
      '0100000000000000000000000000000000000000000000000000000000000000',
      '01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      'ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20',
      'c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562',
      'c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78',
      '47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24',
      'f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72',
      '87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309',
      // These are all bad because they give a nonsquare x^2.
      '26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371',
      '4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f',
      'de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b',
      'bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042',
      '2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08',
      'f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22',
      '8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731',
      '2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b',
      // These are all bad because they give a negative xy value.
      '3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e',
      'a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220',
      'd483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e',
      '8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32',
      '32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b',
      '227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165',
      '5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e',
      '445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b',
      // This is s = -1, which causes y = 0.
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
    ];
    for (const badBytes of badEncodings) {
      expect(() => ExtendedPoint.fromRistrettoBytes(hexToArray(badBytes))).toThrow();
    }
  });
  it('should create right points from hash', async () => {
    const labels = [
      'Ristretto is traditionally a short shot of espresso coffee',
      'made with the normal amount of ground coffee but extracted with',
      'about half the amount of water in the same amount of time',
      'by using a finer grind.',
      'This produces a concentrated shot of coffee per volume.',
      'Just pulling a normal shot short will produce a weaker shot',
      'and is not a Ristretto as some believe.'
    ];
    const encodedHashToPoints = [
      '3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46',
      'f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b',
      '006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826',
      'f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a',
      'ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179',
      'e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628',
      '80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065'
    ];

    for (let i = 0; i < labels.length; i++) {
      const hash = await sha512(Buffer.from(labels[i]));
      const point = ExtendedPoint.fromRistrettoHash(hash);
      expect(arrayToHex(point.toRistrettoBytes())).toBe(encodedHashToPoints[i]);
    }
  });
});

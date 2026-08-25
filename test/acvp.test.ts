import { bytesToHex as hex, hexToBytes as bytes } from '@noble/hashes/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { ed25519 as ed } from './ed25519.helpers.ts';
import { jsonGZ } from './utils.ts';

const PREFIX = './vectors/acvp-vectors/acvp/';
const groups = (suite) => jsonGZ(`${PREFIX}${suite}/internalProjection.json.gz`).testGroups;

describe('ACVP/Ed25519', () => {
  should('KeyGen', () => {
    let count = 0;
    for (const group of groups('EDDSA-KeyGen-1.0')) {
      if (group.curve !== 'ED-25519') continue;
      for (const test of group.tests) {
        eql(hex(ed.getPublicKey(bytes(test.d))), test.q.toLowerCase(), `tcId ${test.tcId}`);
        count++;
      }
    }
    eql(count, 3, 'Ed25519 KeyGen vectors');
  });

  should('KeyVer', () => {
    let count = 0;
    for (const group of groups('EDDSA-KeyVer-1.0')) {
      if (group.curve !== 'ED-25519') continue;
      for (const test of group.tests) {
        let passed = false;
        try {
          ed.Point.fromBytes(bytes(test.q)).assertValidity();
          passed = true;
        } catch {}
        eql(passed, test.testPassed, `tcId ${test.tcId}`);
        count++;
      }
    }
    eql(count, 4, 'Ed25519 KeyVer vectors');
  });

  should('SigGen', () => {
    let count = 0;
    for (const group of groups('EDDSA-SigGen-1.0')) {
      if (group.curve !== 'ED-25519' || group.preHash) continue;
      for (const test of group.tests) {
        eql(test.context, '', `tcId ${test.tcId}: unsupported Ed25519 context`);
        eql(
          hex(ed.sign(bytes(test.message), bytes(group.d))),
          test.signature.toLowerCase(),
          `tcId ${test.tcId}`
        );
        count++;
      }
    }
    eql(count, 42, 'plain Ed25519 SigGen vectors');
  });

  should('SigVer', () => {
    let count = 0;
    for (const group of groups('EDDSA-SigVer-1.0')) {
      if (group.curve !== 'ED-25519' || group.preHash) continue;
      for (const test of group.tests) {
        let passed = false;
        try {
          passed = ed.verify(bytes(test.signature), bytes(test.message), bytes(test.q), {
            zip215: false,
          });
        } catch {}
        eql(passed, test.testPassed, `tcId ${test.tcId}: ${test.reason}`);
        count++;
      }
    }
    eql(count, 5, 'plain Ed25519 SigVer vectors');
  });
});

should.runWhen(import.meta.url);

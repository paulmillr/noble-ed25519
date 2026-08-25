import { sha512 } from '@noble/hashes/sha2.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, strictEqual } from 'node:assert';
import * as ed from '../index.ts';

const filled = (value) => new Uint8Array(32).fill(value);

describe('sign message ownership', () => {
  should('sign snapshots the message before re-entrant hashing', () => {
    const originalHash = ed.hashes.sha512;
    const stateA = filled(0x41);
    const stateB = filled(0x42);
    const message = stateA.slice();
    const secretKey = filled(7);
    ed.hashes.sha512 = sha512;
    const publicKey = ed.getPublicKey(secretKey);
    let calls = 0;
    try {
      ed.hashes.sha512 = (data) => {
        const digest = sha512(data);
        if (++calls === 2) message.set(stateB);
        return digest;
      };
      const signature = ed.sign(message, secretKey);
      strictEqual(calls, 3, 'secret expansion, nonce, and challenge hashes');
      eql(message, stateB, 'test mutation occurred');
      ed.hashes.sha512 = sha512;
      strictEqual(ed.verify(signature, stateA, publicKey), true, 'bound to invocation-time state');
      strictEqual(ed.verify(signature, stateB, publicKey), false, 'not bound to mutated state');
    } finally {
      ed.hashes.sha512 = originalHash;
    }
  });

  should('signAsync snapshots the message across awaited hashing', async () => {
    const originalHash = ed.hashes.sha512;
    const originalHashAsync = ed.hashes.sha512Async;
    const stateA = filled(0x41);
    const stateB = filled(0x42);
    const message = stateA.slice();
    const secretKey = filled(7);
    ed.hashes.sha512 = sha512;
    const publicKey = ed.getPublicKey(secretKey);
    let calls = 0;
    let nonceStarted;
    let resumeNonce;
    const started = new Promise((resolve) => (nonceStarted = resolve));
    const resume = new Promise((resolve) => (resumeNonce = resolve));
    try {
      ed.hashes.sha512Async = async (data) => {
        const digest = sha512(data);
        if (++calls === 2) {
          nonceStarted();
          await resume;
        }
        return digest;
      };
      const signing = ed.signAsync(message, secretKey);
      await started;
      message.set(stateB);
      resumeNonce();
      const signature = await signing;
      strictEqual(calls, 3, 'secret expansion, nonce, and challenge hashes');
      eql(message, stateB, 'test mutation occurred');
      strictEqual(ed.verify(signature, stateA, publicKey), true, 'bound to invocation-time state');
      strictEqual(ed.verify(signature, stateB, publicKey), false, 'not bound to mutated state');
    } finally {
      resumeNonce?.();
      ed.hashes.sha512 = originalHash;
      ed.hashes.sha512Async = originalHashAsync;
    }
  });
});

should.runWhen(import.meta.url);

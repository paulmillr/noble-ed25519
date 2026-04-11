import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import * as ed from '../index.ts';

describe('hashes', () => {
  should(
    'ed.hash() rejects a non-Uint8Array message before calling the configured SHA-512 provider',
    () => {
      const prev = ed.hashes.sha512;
      let called = false;
      try {
        ed.hashes.sha512 = () => {
          called = true;
          return new Uint8Array(64);
        };
        throws(() => ed.hash('abc' as unknown as Uint8Array), /"message" expected Uint8Array/);
        eql(called, false);
      } finally {
        ed.hashes.sha512 = prev;
      }
    }
  );

  should(
    'ed.hash() rejects configured SHA-512 providers that return the wrong type or a digest not exactly 64 bytes',
    () => {
      const prev = ed.hashes.sha512;
      try {
        ed.hashes.sha512 = () => new Uint8Array([1, 2, 3]);
        throws(() => ed.hash(new Uint8Array([9])), /digest/);
        ed.hashes.sha512 = () => 'not-bytes' as unknown as Uint8Array;
        throws(() => ed.hash(new Uint8Array([9])), /digest/);
      } finally {
        ed.hashes.sha512 = prev;
      }
    }
  );

  should(
    'getPublicKey()/getPublicKeyAsync() reject configured providers that return digests not exactly 64 bytes',
    async () => {
      const sk = new Uint8Array(32).fill(7);
      const prevSync = ed.hashes.sha512;
      try {
        ed.hashes.sha512 = () => new Uint8Array([1, 2, 3]);
        throws(() => ed.getPublicKey(sk), /digest/);
      } finally {
        ed.hashes.sha512 = prevSync;
      }
      const prevAsync = ed.hashes.sha512Async;
      try {
        ed.hashes.sha512Async = async () => new Uint8Array([1, 2, 3]);
        await rejects(() => ed.getPublicKeyAsync(sk), /digest/);
      } finally {
        ed.hashes.sha512Async = prevAsync;
      }
    }
  );

  should(
    'sign/signAsync/verify/verifyAsync reject configured SHA-512 providers that return digests not exactly 64 bytes',
    async () => {
      const msg = new Uint8Array([9]);
      const sk = new Uint8Array(32).fill(7);
      const sig = new Uint8Array(64);
      const pk = new Uint8Array(32);
      const prevSync = ed.hashes.sha512;
      try {
        ed.hashes.sha512 = () => new Uint8Array([1, 2, 3]);
        throws(() => ed.sign(msg, sk), /digest/);
        throws(() => ed.verify(sig, msg, pk), /digest/);
      } finally {
        ed.hashes.sha512 = prevSync;
      }
      const prevAsync = ed.hashes.sha512Async;
      try {
        ed.hashes.sha512Async = async () => new Uint8Array([1, 2, 3]);
        await rejects(() => ed.signAsync(msg, sk), /digest/);
        await rejects(() => ed.verifyAsync(sig, msg, pk), /digest/);
      } finally {
        ed.hashes.sha512Async = prevAsync;
      }
    }
  );
});

should.runWhen(import.meta.url);

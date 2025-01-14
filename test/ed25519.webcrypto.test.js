import { webcrypto } from 'node:crypto';
// @ts-ignore
if (!globalThis.crypto) globalThis.crypto = webcrypto;
import './ed25519.test.js';
// Force ESM import to execute
import { should } from 'micro-should';
should.runWhen(import.meta.url);

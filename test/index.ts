import { should } from '@paulmillr/jsbt/test.js';
import './acvp.test.ts';
import './ed25519.test.ts';
import './hashes.test.ts';
import './point.test.ts';
import './sign.test.ts';
import './utils.test.ts';

should.runWhen(import.meta.url);

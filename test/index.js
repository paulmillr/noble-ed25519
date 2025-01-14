import { should } from 'micro-should';
import './basic.test.js';
import './ed25519.test.js';
import './utils.test.js';

should.runWhen(import.meta.url);
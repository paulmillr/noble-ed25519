import { should } from 'micro-should';
import './ed25519.test.js';
import './point.test.js';
import './utils.test.js';

should.runWhen(import.meta.url);

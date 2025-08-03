import { should } from 'micro-should';
import './ed25519.test.ts';
import './point.test.ts';
import './utils.test.ts';

should.runWhen(import.meta.url);

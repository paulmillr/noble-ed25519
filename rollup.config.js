import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default {
  input: 'index.js',
  output: {
    file: 'build/noble-ed25519.js',
    format: 'umd',
    name: 'nobleEd25519',
    exports: 'named',
    preferConst: true,
  },
  plugins: [resolve(), commonjs()],
};

import resolve from '@rollup/plugin-node-resolve';

export default {
  input: 'lib/esm/index.js',
  output: {
    file: 'build/noble-ed25519.js',
    format: 'umd',
    name: 'nobleEd25519',
    exports: 'named',
    preferConst: true,
  },
  plugins: [resolve({ browser: true })],
};

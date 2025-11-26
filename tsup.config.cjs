const { defineConfig } = require('tsup');

module.exports = defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  shims: true,
  splitting: false,
  target: 'es2020',
  platform: 'node',
  external: ['esbuild'],
  esbuildOptions(options) {
    options.logOverride = { 'require-resolve-not-external': 'silent' };
  },
});

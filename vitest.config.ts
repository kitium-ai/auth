import { defineConfig } from 'vitest/config';
import { nodePreset } from '@kitiumai/vitest-helpers/setup/presets';

export default defineConfig({
  test: {
    ...nodePreset,
    globals: true,
    environment: 'node',
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      'src/__tests__/2fa.test.ts',
      'src/__tests__/sso.test.ts',
      'src/__tests__/rbac.test.ts',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json'],
      thresholds: {
        lines: 90,
        functions: 90,
        branches: 90,
        statements: 90,
      },
      exclude: [
        '**/*.test.ts',
        '**/*.spec.ts',
        'dist/**',
        'node_modules/**',
      ],
    },
  },
});

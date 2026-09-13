import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const rootDir = fileURLToPath(new URL('.', import.meta.url));

/**
 * Kept separate from vite.config.ts on purpose: the app config is tuned for
 * production builds (Tailwind, HMR switches) and the test run wants jsdom
 * instead. Mixing them means a change to one quietly changes the other.
 *
 * `globals` is deliberately off -- every test imports what it uses, so `tsc
 * --noEmit` still type-checks the suite instead of waving it through.
 */
export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@': rootDir } },
  test: {
    environment: 'jsdom',
    include: ['tests/frontend/**/*.test.{ts,tsx}'],
    setupFiles: ['tests/frontend/setup.ts'],
    restoreMocks: true,
  },
});

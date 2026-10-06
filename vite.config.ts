import { configDefaults, defineConfig } from 'vitest/config';

// base must match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-wep-crack/
export default defineConfig({
  base: '/crypto-lab-wep-crack/',
  worker: { format: 'es' },
  test: {
    // Colocated unit tests only; keep the Playwright specs in e2e/ out of the
    // Vitest run (master template §1).
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
});

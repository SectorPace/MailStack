import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

/**
 * vitest only wires up testing-library's automatic cleanup when `globals` is
 * enabled. We keep globals off so `tsc --noEmit` still type-checks the suite,
 * which means cleanup has to be registered by hand -- otherwise every render
 * appends to the same document and one test's nodes satisfy the next test's
 * `queryByText`, quietly turning negative assertions into passing ones.
 */
afterEach(() => {
  cleanup();
});

// jsdom does not implement matchMedia, and several components call it through
// the theme hook. Without this the suite dies before any assertion runs.
if (!window.matchMedia) {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}

/**
 * getErrorMessage decides what the operator actually reads when something
 * breaks. It is the difference between "PRIVILEGED_HELPER_UNAVAILABLE" and a
 * sentence telling them to finish the install, so it gets real tests rather
 * than a grep for the function name.
 */
import { describe, expect, it } from 'vitest';
import { ApiError, getErrorMessage } from '../../src/utils/errors';

describe('getErrorMessage', () => {
  it('falls back when there is nothing to say', () => {
    expect(getErrorMessage(null)).toBe('An unexpected error occurred');
    expect(getErrorMessage(undefined)).toBe('An unexpected error occurred');
    expect(getErrorMessage('')).toBe('An unexpected error occurred');
  });

  it('honours a custom fallback', () => {
    expect(getErrorMessage(null, 'boom')).toBe('boom');
  });

  it('reads strings, Errors and plain objects', () => {
    expect(getErrorMessage('disk full')).toBe('disk full');
    expect(getErrorMessage(new Error('disk full'))).toBe('disk full');
    expect(getErrorMessage({ message: 'disk full' })).toBe('disk full');
    expect(getErrorMessage({ error: 'disk full' })).toBe('disk full');
  });

  it('prefers .message over .error when both are present', () => {
    expect(getErrorMessage({ message: 'specific', error: 'generic' })).toBe('specific');
  });

  it('unwraps an ApiError to its message', () => {
    expect(getErrorMessage(new ApiError('AUTH_REQUIRED', 401, 'no_session'))).toBe('AUTH_REQUIRED');
  });

  it('translates privileged-helper failures into an actionable sentence', () => {
    // These three codes all mean the same thing to the operator: the root
    // helper is not wired up. They must not reach the UI as raw codes.
    for (const raw of [
      'PRIVILEGED_HELPER_UNAVAILABLE',
      'helper failure: exited 1',
      'PRIVILEGED_OPERATION_FAILED',
    ]) {
      const message = getErrorMessage(new Error(raw));
      expect(message).toContain('特权助手未就绪');
      expect(message).not.toContain(raw);
    }
  });

  it('translates a privileged-helper timeout separately', () => {
    const message = getErrorMessage(new Error('PRIVILEGED_HELPER_TIMEOUT after 45s'));
    expect(message).toContain('特权操作超时');
    expect(message).not.toContain('PRIVILEGED_HELPER_TIMEOUT');
  });

  it('does not crash on a value that cannot be stringified', () => {
    // A circular object makes JSON.stringify throw. That path used to be
    // guarded, and the guard is easy to lose.
    const circular: Record<string, unknown> = { name: 'loop' };
    circular.self = circular;
    expect(() => getErrorMessage(circular)).not.toThrow();
    expect(typeof getErrorMessage(circular)).toBe('string');
  });

  it('never returns an empty string', () => {
    const empty: Record<string, unknown> = { message: '', error: '' };
    expect(getErrorMessage(empty).length).toBeGreaterThan(0);
  });
});

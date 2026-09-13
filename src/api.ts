import type {
  SessionInfo,
  TwoFactorBeginResult,
  TwoFactorDisableResult,
  TwoFactorEnableResult,
  TwoFactorStatus,
} from './types';

let csrf = '';

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

const clearSession = () => {
  csrf = '';
  window.dispatchEvent(new CustomEvent('mailstack:auth-required'));
};

const responseError = (payload: any, fallback: string) => {
  if (typeof payload.error === 'object' && payload.error?.message) return payload.error.message;
  return payload.message || payload.error || fallback;
};

export async function login(username: string, password: string, code?: string) {
  const r = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password, ...(code ? { code } : {}) })
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    throw new ApiError(responseError(j, 'LOGIN_FAILED'), r.status, j.error?.code || 'LOGIN_FAILED');
  }
  csrf = typeof j.csrf === 'string' ? j.csrf : '';
  return j;
}

export async function api<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const method = init.method || 'GET';
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    ...((init.headers as Record<string, string>) || {})
  };
  if (!['GET', 'HEAD'].includes(method)) headers['x-csrf-token'] = csrf;
  const r = await fetch(path, { ...init, headers, credentials: 'same-origin' });
  const j = await r.json().catch(() => ({}));
  if (r.status === 401) {
    clearSession();
    throw new ApiError('AUTH_REQUIRED', 401, j.error?.code || 'AUTH_REQUIRED');
  }
  if (!r.ok) {
    throw new ApiError(responseError(j, 'REQUEST_FAILED'), r.status, j.error?.code || 'REQUEST_FAILED');
  }
  return j;
}

export async function getTwoFactorStatus(): Promise<TwoFactorStatus> {
  return api('/api/admin/2fa');
}

export async function beginTwoFactor(code?: string): Promise<TwoFactorBeginResult> {
  // When 2FA is already enabled, beginning a re-enrollment requires a valid
  // TOTP/recovery code; the server rejects the call without one.
  return api('/api/admin/2fa/begin', {
    method: 'POST',
    body: JSON.stringify({ code: code || '' }),
  });
}

export async function enableTwoFactor(code: string): Promise<TwoFactorEnableResult> {
  return api('/api/admin/2fa/enable', {
    method: 'POST',
    body: JSON.stringify({ code }),
  });
}

export async function disableTwoFactor(code: string): Promise<TwoFactorDisableResult> {
  return api('/api/admin/2fa/disable', {
    method: 'POST',
    body: JSON.stringify({ code }),
  });
}

export async function listSessions(): Promise<{ sessions: SessionInfo[] }> {
  return api('/api/auth/sessions');
}

export async function revokeSession(id: string): Promise<{ ok: true }> {
  return api('/api/auth/sessions/revoke', {
    method: 'POST',
    body: JSON.stringify({ id }),
  });
}

export async function revokeOtherSessions(): Promise<{ ok: true; revoked: number }> {
  return api('/api/auth/sessions', { method: 'DELETE' });
}

export async function session() {
  const r = await fetch('/api/auth/session', { credentials: 'same-origin' });
  if (!r.ok) {
    if (r.status === 401) clearSession();
    return false;
  }
  const j = await r.json().catch(() => ({}));
  csrf = typeof j.csrf === 'string' ? j.csrf : '';
  return Boolean(j.ok);
}

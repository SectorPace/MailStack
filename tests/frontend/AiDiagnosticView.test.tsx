/**
 * AiDiagnosticView builds the DNS record set an operator copies into their
 * registrar. When the server's public IP cannot be read, the A record and the
 * SPF record used to silently disappear from that table -- the operator copied
 * a five-record set that was missing two of them, with nothing on screen
 * explaining why. These tests pin the warning that replaced the silence.
 */
import { render, screen, waitFor } from '@testing-library/react';
import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

const apiMock = vi.fn();
// Hoisted so the mock factory below can read it: vi.mock factories run before
// any top-level const is initialised.
const { languageRef } = vi.hoisted(() => ({ languageRef: { current: 'zh' } }));

vi.mock('../../src/api', () => ({
  api: (...args: unknown[]) => apiMock(...args),
}));

vi.mock('../../src/context/AppContext', () => ({
  useApp: () => ({
    domains: [],
    language: languageRef.current,
    themeMode: 'dark',
    setCurrentSection: () => {},
    showToast: () => {},
  }),
}));

vi.mock('../../src/components/dns/AiDnsDiagnostic', () => ({
  AiDnsDiagnostic: () => React.createElement('div', { 'data-testid': 'dns-panel' }),
}));

vi.mock('../../src/components/common/LiquidGlass', () => ({
  LiquidGlass: ({ children }: { children?: React.ReactNode }) =>
    React.createElement('div', { 'data-testid': 'glass' }, children),
}));

const { AiDiagnosticView } = await import('../../src/components/views/AiDiagnosticView');

afterEach(() => {
  apiMock.mockReset();
  languageRef.current = 'zh';
});

describe('AiDiagnosticView identity lookup', () => {
  it('says nothing when the server IP resolves', async () => {
    apiMock.mockResolvedValue({ identity: { serverIp: '203.0.113.10', domain: 'example.com' } });
    render(React.createElement(AiDiagnosticView));

    await waitFor(() => expect(apiMock).toHaveBeenCalledWith('/api/setup/status'));
    expect(screen.queryByText('无法读取服务器公网 IP')).toBeNull();
  });

  it('warns instead of silently omitting the A and SPF records', async () => {
    apiMock.mockRejectedValue(new Error('network down'));
    render(React.createElement(AiDiagnosticView));

    await waitFor(() =>
      expect(screen.getByText('无法读取服务器公网 IP')).toBeInTheDocument(),
    );
    // The message has to say which records are missing, otherwise the operator
    // still does not know what they are looking at.
    expect(screen.getByText(/A 记录与 SPF 记录/)).toBeInTheDocument();
  });

  it('renders the English copy when the UI language is English', async () => {
    languageRef.current = 'en';
    apiMock.mockRejectedValue(new Error('network down'));
    render(React.createElement(AiDiagnosticView));

    await waitFor(() =>
      expect(screen.getByText('Server public IP unavailable')).toBeInTheDocument(),
    );
    expect(screen.getByText(/A and SPF records/)).toBeInTheDocument();
    expect(screen.queryByText('无法读取服务器公网 IP')).toBeNull();
  });
});

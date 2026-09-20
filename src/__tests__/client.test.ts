import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getExternalScan, listExternalScans } from '../client.js';
import { TelivyApiError, TelivyAuthError, TelivyRateLimitError } from '../types.js';
import { jsonResponse } from './test-helpers.js';

describe('client', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends the API key as the x-api-key header', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ message: 'ok', assessments: [], total: 0 }));

    await listExternalScans(creds);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api-v1.telivy.com/api/v1/security/external-scans');
    expect(init.headers['x-api-key']).toBe('key-1');
  });

  it('forwards list params as query string', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ message: 'ok', assessments: [], total: 0 }));

    await listExternalScans(creds, { search: 'acme', limit: 25, offset: 50, sortOrder: 'ASC' });

    const [url] = fetchMock.mock.calls[0];
    const parsed = new URL(url as string);
    expect(parsed.searchParams.get('search')).toBe('acme');
    expect(parsed.searchParams.get('limit')).toBe('25');
    expect(parsed.searchParams.get('offset')).toBe('50');
    expect(parsed.searchParams.get('sortOrder')).toBe('ASC');
  });

  it('throws TelivyAuthError distinctly on HTTP 401 (invalid credentials)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ message: 'Unauthorized' }, 401));

    await expect(getExternalScan(creds, 'scan-1')).rejects.toThrow(TelivyAuthError);
  });

  it('throws TelivyRateLimitError distinctly on HTTP 429 (rate limited), not TelivyAuthError', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ message: 'Too Many Requests' }, 429));

    await expect(getExternalScan(creds, 'scan-1')).rejects.toThrow(TelivyRateLimitError);
    await expect(getExternalScan(creds, 'scan-1')).rejects.not.toThrow(TelivyAuthError);
  });

  it('throws a generic TelivyApiError on any other non-2xx response', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ message: 'Internal Server Error' }, 500));

    await expect(getExternalScan(creds, 'scan-1')).rejects.toThrow(TelivyApiError);
  });
});

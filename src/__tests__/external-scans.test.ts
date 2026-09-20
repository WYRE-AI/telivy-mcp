import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleExternalScanTool } from '../tools/external-scans.js';
import { runWithCredentials } from '../client.js';
import { jsonResponse, textOf } from './test-helpers.js';

describe('handleExternalScanTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('telivy_list_external_scans forwards list params and returns the parsed body', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ message: 'ok', assessments: [{ id: 'scan-1' }], total: 1 })
    );

    const result = await runWithCredentials(creds, () =>
      handleExternalScanTool('telivy_list_external_scans', { limit: 10, search: 'acme' })
    );

    expect(result.isError).toBeUndefined();
    expect(JSON.parse(textOf(result)).total).toBe(1);

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/api/v1/security/external-scans');
    expect(url.searchParams.get('limit')).toBe('10');
    expect(url.searchParams.get('search')).toBe('acme');
  });

  it('telivy_get_external_scan fetches by ID', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ id: 'scan-1', scanStatus: 'completed' }));

    const result = await runWithCredentials(creds, () =>
      handleExternalScanTool('telivy_get_external_scan', { id: 'scan-1' })
    );

    expect(result.isError).toBeUndefined();
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toBe('https://api-v1.telivy.com/api/v1/security/external-scans/scan-1');
  });

  it('telivy_list_external_scan_findings fetches the findings sub-resource', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ name: 'Open Ports', slug: 'open-ports' }]));

    const result = await runWithCredentials(creds, () =>
      handleExternalScanTool('telivy_list_external_scan_findings', { id: 'scan-1' })
    );

    expect(result.isError).toBeUndefined();
    expect(textOf(result)).toContain('Open Ports');
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toBe('https://api-v1.telivy.com/api/v1/security/external-scans/scan-1/findings');
  });

  it('telivy_get_external_scan_finding fetches by id and slug', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ id: 'f1', slug: 'open-ports', domain: 'example.com' }));

    const result = await runWithCredentials(creds, () =>
      handleExternalScanTool('telivy_get_external_scan_finding', { id: 'scan-1', slug: 'open-ports' })
    );

    expect(result.isError).toBeUndefined();
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toBe('https://api-v1.telivy.com/api/v1/security/external-scans/scan-1/findings/open-ports');
  });

  it('telivy_get_breach_data fetches the breach-data sub-resource', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ id: 'b1', email: 'user@example.com' }]));

    const result = await runWithCredentials(creds, () =>
      handleExternalScanTool('telivy_get_breach_data', { id: 'scan-1' })
    );

    expect(result.isError).toBeUndefined();
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toBe('https://api-v1.telivy.com/api/v1/security/external-scans/scan-1/breach-data');
  });

  it('returns an error result when credentials are missing', async () => {
    const result = await handleExternalScanTool('telivy_list_external_scans', {});
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('TELIVY_API_KEY');
  });

  it('surfaces a distinct error message on HTTP 401', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ message: 'Unauthorized' }, 401));

    const result = await runWithCredentials(creds, () =>
      handleExternalScanTool('telivy_get_external_scan', { id: 'scan-1' })
    );

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/401/);
  });
});

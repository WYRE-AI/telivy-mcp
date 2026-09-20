import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleMiscTool } from '../tools/misc.js';
import { runWithCredentials } from '../client.js';
import { jsonResponse, textOf } from './test-helpers.js';

describe('handleMiscTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('telivy_get_agent_versions fetches with no params', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ windows: '3.2.1', mac: '3.2.0' }));

    const result = await runWithCredentials(creds, () => handleMiscTool('telivy_get_agent_versions', {}));

    expect(result.isError).toBeUndefined();
    expect(fetchMock.mock.calls[0][0]).toBe('https://api-v1.telivy.com/api/v1/security/agent-versions');
    expect(JSON.parse(textOf(result)).windows).toBe('3.2.1');
  });

  it('telivy_get_finding fetches a top-level finding by slug', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ id: 'f1', slug: 'TYPO_SQUATTING', value: 'high' }));

    const result = await runWithCredentials(creds, () =>
      handleMiscTool('telivy_get_finding', { slug: 'TYPO_SQUATTING' })
    );

    expect(result.isError).toBeUndefined();
    expect(fetchMock.mock.calls[0][0]).toBe('https://api-v1.telivy.com/api/v1/security/findings/TYPO_SQUATTING');
  });

  it('telivy_get_risk_progress forwards both timestamp group params', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ scans: {}, report: { new: [], resolved: [], regressed: [], open: [] } })
    );

    await runWithCredentials(creds, () =>
      handleMiscTool('telivy_get_risk_progress', {
        id: 'ra-1',
        currentTimestampGroup: '2026-09-01T00:00:00Z',
        compareWithTimestampGroup: '2026-08-01T00:00:00Z',
      })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/api/v1/security/ra-1/risk');
    expect(url.searchParams.get('currentTimestampGroup')).toBe('2026-09-01T00:00:00Z');
    expect(url.searchParams.get('compareWithTimestampGroup')).toBe('2026-08-01T00:00:00Z');
  });

  it('telivy_get_risk_progress omits compareWithTimestampGroup when not supplied', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ scans: {}, report: { new: [], resolved: [], regressed: [], open: [] } })
    );

    await runWithCredentials(creds, () =>
      handleMiscTool('telivy_get_risk_progress', { id: 'ra-1', currentTimestampGroup: '2026-09-01T00:00:00Z' })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.searchParams.has('compareWithTimestampGroup')).toBe(false);
  });
});

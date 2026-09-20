import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleRiskAssessmentTool } from '../tools/risk-assessments.js';
import { runWithCredentials } from '../client.js';
import { jsonResponse, textOf } from './test-helpers.js';

describe('handleRiskAssessmentTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('telivy_list_risk_assessments forwards scanStatus as repeated query params', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ message: 'ok', assessments: [], total: 0 }));

    await runWithCredentials(creds, () =>
      handleRiskAssessmentTool('telivy_list_risk_assessments', {
        scanStatus: ['in_progress', 'report_completed'],
      })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.searchParams.getAll('scanStatus')).toEqual(['in_progress', 'report_completed']);
  });

  it('telivy_get_risk_assessment fetches by ID', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ id: 'ra-1', scanStatus: 'in_progress' }));

    const result = await runWithCredentials(creds, () =>
      handleRiskAssessmentTool('telivy_get_risk_assessment', { id: 'ra-1' })
    );

    expect(result.isError).toBeUndefined();
    expect(fetchMock.mock.calls[0][0]).toBe('https://api-v1.telivy.com/api/v1/security/risk-assessments/ra-1');
  });

  it('telivy_list_risk_assessment_devices lists devices for an assessment', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ id: 'd1', hostname: 'WS-1' }]));

    const result = await runWithCredentials(creds, () =>
      handleRiskAssessmentTool('telivy_list_risk_assessment_devices', { id: 'ra-1' })
    );

    expect(result.isError).toBeUndefined();
    expect(fetchMock.mock.calls[0][0]).toBe(
      'https://api-v1.telivy.com/api/v1/security/risk-assessments/ra-1/devices'
    );
  });

  it('telivy_get_risk_assessment_device fetches a single device by id + deviceId', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ id: 'd1', hostname: 'WS-1' }));

    await runWithCredentials(creds, () =>
      handleRiskAssessmentTool('telivy_get_risk_assessment_device', { id: 'ra-1', deviceId: 'd1' })
    );

    expect(fetchMock.mock.calls[0][0]).toBe(
      'https://api-v1.telivy.com/api/v1/security/risk-assessments/ra-1/devices/d1'
    );
  });

  it('telivy_get_risk_assessment_scan_status fetches the scan-status sub-resource', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ totalDevices: 2, completedDevices: 1, inProgressDevices: 1, allScansCompleted: false, devices: [] })
    );

    const result = await runWithCredentials(creds, () =>
      handleRiskAssessmentTool('telivy_get_risk_assessment_scan_status', { id: 'ra-1' })
    );

    expect(result.isError).toBeUndefined();
    expect(fetchMock.mock.calls[0][0]).toBe(
      'https://api-v1.telivy.com/api/v1/security/risk-assessments/ra-1/scan-status'
    );
  });

  it('telivy_list_m365_users fetches the m365-users sub-resource', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ configured: true, connectionStatus: 'connected', data: {}, lastSyncedAt: '2026-09-01T00:00:00Z' })
    );

    await runWithCredentials(creds, () => handleRiskAssessmentTool('telivy_list_m365_users', { id: 'ra-1' }));

    expect(fetchMock.mock.calls[0][0]).toBe(
      'https://api-v1.telivy.com/api/v1/security/risk-assessments/ra-1/m365-users'
    );
  });

  it('telivy_list_gws_users fetches the gws-users sub-resource', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ configured: false, connectionStatus: 'not_configured', data: {} })
    );

    await runWithCredentials(creds, () => handleRiskAssessmentTool('telivy_list_gws_users', { id: 'ra-1' }));

    expect(fetchMock.mock.calls[0][0]).toBe(
      'https://api-v1.telivy.com/api/v1/security/risk-assessments/ra-1/gws-users'
    );
  });

  it('telivy_get_pii_summary fetches the pii-summary sub-resource', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ distributionByType: [], deviceSummaries: [], totalSensitiveFiles: 0, totalDataRisk: 0 })
    );

    const result = await runWithCredentials(creds, () =>
      handleRiskAssessmentTool('telivy_get_pii_summary', { id: 'ra-1' })
    );

    expect(result.isError).toBeUndefined();
    expect(fetchMock.mock.calls[0][0]).toBe(
      'https://api-v1.telivy.com/api/v1/security/risk-assessments/ra-1/pii-summary'
    );
  });
});

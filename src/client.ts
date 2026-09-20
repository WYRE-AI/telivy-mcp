import { AsyncLocalStorage } from 'node:async_hooks';
import { logger } from './utils/logger.js';
import {
  TelivyApiError,
  TelivyAuthError,
  TelivyRateLimitError,
} from './types.js';
import type {
  AgentVersionsDTO,
  AssessmentScanStatusDTO,
  BreachDataDTO,
  CloudUsersResponseDTO,
  ExternalScanDTO,
  ExternalScansDTO,
  FindingsProgressReportResponseDTO,
  FindingWithTaskResponseDTO,
  DeepScanTargetDTO,
  ListParams,
  ListRiskAssessmentsParams,
  PiiSummaryDataDTO,
  RiskAssessmentDTO,
  RiskAssessmentsDTO,
  SecurityFindingDetailDTO,
  SecurityFindingDTO,
  TelivyCredentials,
} from './types.js';

export const BASE_URL = 'https://api-v1.telivy.com';

// Request-scoped credential store. In gateway mode the HTTP layer runs each
// request inside runWithCredentials({apiKey}); getCredentials() reads from
// it. Falls back to process.env for stdio/single-tenant mode.
const credStore = new AsyncLocalStorage<TelivyCredentials>();

export function runWithCredentials<T>(creds: TelivyCredentials, fn: () => T): T {
  return credStore.run(creds, fn);
}

export function getCredentials(): TelivyCredentials | null {
  const scoped = credStore.getStore();
  if (scoped?.apiKey) return scoped;
  const apiKey = process.env.TELIVY_API_KEY;
  if (!apiKey) {
    logger.warn('Missing credentials', { hasApiKey: !!apiKey });
    return null;
  }
  return { apiKey };
}

function buildQuery(params: Record<string, unknown> = {}): URLSearchParams {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const v of value) qs.append(key, String(v));
      continue;
    }
    qs.append(key, String(value));
  }
  return qs;
}

async function doGet<T>(
  creds: TelivyCredentials,
  path: string,
  query?: Record<string, unknown>
): Promise<T> {
  const qs = query ? buildQuery(query).toString() : '';
  const url = `${BASE_URL}${path}${qs ? `?${qs}` : ''}`;
  const res = await fetch(url, {
    method: 'GET',
    headers: { 'x-api-key': creds.apiKey, Accept: 'application/json' },
    signal: AbortSignal.timeout(15_000),
  });

  // 401 (invalid credentials) and 429 (rate-limited) are distinct failure
  // modes with distinct remediations - grouping them under one generic
  // auth-error class hides a transient rate limit behind a message that
  // reads like a bad API key.
  if (res.status === 401) {
    throw new TelivyAuthError(`Telivy rejected the API key (HTTP 401): ${path}`);
  }
  if (res.status === 429) {
    throw new TelivyRateLimitError(`Telivy rate-limited the request (HTTP 429): ${path}`);
  }
  if (!res.ok) {
    throw new TelivyApiError(`Telivy ${path} failed: HTTP ${res.status}`, res.status);
  }
  return (await res.json()) as T;
}

// ---------------------------------------------------------------------
// External scans
// ---------------------------------------------------------------------

/** GET /api/v1/security/external-scans - list external scans (paginated, filterable). */
export async function listExternalScans(
  creds: TelivyCredentials,
  params: ListParams = {}
): Promise<ExternalScansDTO> {
  return doGet(creds, '/api/v1/security/external-scans', { ...params });
}

/** GET /api/v1/security/external-scans/{id} - a single external scan by assessment ID. */
export async function getExternalScan(creds: TelivyCredentials, id: string): Promise<ExternalScanDTO> {
  return doGet(creds, `/api/v1/security/external-scans/${encodeURIComponent(id)}`);
}

/** GET /api/v1/security/external-scans/{id}/findings - findings for an external scan. */
export async function listExternalScanFindings(
  creds: TelivyCredentials,
  id: string
): Promise<SecurityFindingDTO[]> {
  return doGet(creds, `/api/v1/security/external-scans/${encodeURIComponent(id)}/findings`);
}

/** GET /api/v1/security/external-scans/{id}/findings/{slug} - a single finding's details by slug. */
export async function getExternalScanFinding(
  creds: TelivyCredentials,
  id: string,
  slug: string
): Promise<SecurityFindingDetailDTO> {
  return doGet(
    creds,
    `/api/v1/security/external-scans/${encodeURIComponent(id)}/findings/${encodeURIComponent(slug)}`
  );
}

/** GET /api/v1/security/external-scans/{id}/breach-data - breach records surfaced for the assessment's domain(s). */
export async function getBreachData(creds: TelivyCredentials, id: string): Promise<BreachDataDTO[]> {
  return doGet(creds, `/api/v1/security/external-scans/${encodeURIComponent(id)}/breach-data`);
}

// ---------------------------------------------------------------------
// Risk assessments
// ---------------------------------------------------------------------

/** GET /api/v1/security/risk-assessments - list risk assessments (paginated, filterable). */
export async function listRiskAssessments(
  creds: TelivyCredentials,
  params: ListRiskAssessmentsParams = {}
): Promise<RiskAssessmentsDTO> {
  return doGet(creds, '/api/v1/security/risk-assessments', { ...params });
}

/** GET /api/v1/security/risk-assessments/{id} - a single risk assessment by ID. */
export async function getRiskAssessment(creds: TelivyCredentials, id: string): Promise<RiskAssessmentDTO> {
  return doGet(creds, `/api/v1/security/risk-assessments/${encodeURIComponent(id)}`);
}

/** GET /api/v1/security/risk-assessments/{id}/devices - all deep-scan devices for a risk assessment. */
export async function listRiskAssessmentDevices(
  creds: TelivyCredentials,
  id: string
): Promise<DeepScanTargetDTO[]> {
  return doGet(creds, `/api/v1/security/risk-assessments/${encodeURIComponent(id)}/devices`);
}

/** GET /api/v1/security/risk-assessments/{id}/devices/{deviceId} - a single device by ID. */
export async function getRiskAssessmentDevice(
  creds: TelivyCredentials,
  id: string,
  deviceId: string
): Promise<DeepScanTargetDTO> {
  return doGet(
    creds,
    `/api/v1/security/risk-assessments/${encodeURIComponent(id)}/devices/${encodeURIComponent(deviceId)}`
  );
}

/** GET /api/v1/security/risk-assessments/{id}/scan-status - scan completion status across all devices. */
export async function getRiskAssessmentScanStatus(
  creds: TelivyCredentials,
  id: string
): Promise<AssessmentScanStatusDTO> {
  return doGet(creds, `/api/v1/security/risk-assessments/${encodeURIComponent(id)}/scan-status`);
}

/** GET /api/v1/security/risk-assessments/{id}/m365-users - M365 user accounts with login/MFA status. */
export async function listM365Users(creds: TelivyCredentials, id: string): Promise<CloudUsersResponseDTO> {
  return doGet(creds, `/api/v1/security/risk-assessments/${encodeURIComponent(id)}/m365-users`);
}

/** GET /api/v1/security/risk-assessments/{id}/gws-users - Google Workspace user accounts with login/2SV status. */
export async function listGwsUsers(creds: TelivyCredentials, id: string): Promise<CloudUsersResponseDTO> {
  return doGet(creds, `/api/v1/security/risk-assessments/${encodeURIComponent(id)}/gws-users`);
}

/** GET /api/v1/security/risk-assessments/{id}/pii-summary - PII exposure summary across all devices. */
export async function getPiiSummary(creds: TelivyCredentials, id: string): Promise<PiiSummaryDataDTO> {
  return doGet(creds, `/api/v1/security/risk-assessments/${encodeURIComponent(id)}/pii-summary`);
}

// ---------------------------------------------------------------------
// Findings, agent versions, risk progress
// ---------------------------------------------------------------------

/** GET /api/v1/security/agent-versions - latest Telivy deep-scan agent versions (Windows/Mac). */
export async function getAgentVersions(creds: TelivyCredentials): Promise<AgentVersionsDTO> {
  return doGet(creds, '/api/v1/security/agent-versions');
}

/** GET /api/v1/security/findings/{slug} - top-level finding details by slug (e.g. TYPO_SQUATTING, PERSONAL_EMAILS). */
export async function getFinding(creds: TelivyCredentials, slug: string): Promise<FindingWithTaskResponseDTO> {
  return doGet(creds, `/api/v1/security/findings/${encodeURIComponent(slug)}`);
}

/** GET /api/v1/security/{id}/risk - progress report comparing two scan timestamp groups. */
export async function getRiskProgress(
  creds: TelivyCredentials,
  id: string,
  currentTimestampGroup: string,
  compareWithTimestampGroup?: string
): Promise<FindingsProgressReportResponseDTO> {
  return doGet(creds, `/api/v1/security/${encodeURIComponent(id)}/risk`, {
    currentTimestampGroup,
    compareWithTimestampGroup,
  });
}

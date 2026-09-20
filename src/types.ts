/**
 * Telivy authenticates every request with a single static API key issued
 * from the Telivy Portal (Account > Integrations). An OAuth2/Auth0 implicit
 * flow also exists (per the vendor's own published OpenAPI spec), but the
 * API-key path is the documented default for MSP integrations and needs no
 * second credential field, so that's what this connector uses.
 */
export interface TelivyCredentials {
  apiKey: string;
}

/** Thrown when Telivy rejects the API key (HTTP 401) - distinct from rate limiting so callers get an honest error. */
export class TelivyAuthError extends Error {}

/** Thrown when Telivy rate-limits the request (HTTP 429) - distinct from an auth failure. */
export class TelivyRateLimitError extends Error {}

/** Thrown for any other non-2xx / unexpected vendor response. */
export class TelivyApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
  }
}

/**
 * Sort/filter enums from Telivy's published OpenAPI spec
 * (https://api-v1.telivy.com/api-docs/security-json).
 */
export type AssessmentSortBy = 'organizationName' | 'assessmentStatus' | 'createdAt' | 'updatedAt';
export type SortOrder = 'DESC' | 'ASC';
export type RiskAssessmentStatus = 'not_started' | 'in_progress' | 'report_completed' | 'archived';

export interface ListParams {
  search?: string;
  assessmentSortBy?: AssessmentSortBy;
  sortOrder?: SortOrder;
  offset?: number;
  limit?: number;
  /** TELIVY_ADMIN-only: scope results to a specific agency. Ignored by non-admin API keys. */
  agencyId?: string;
}

export interface ListRiskAssessmentsParams extends ListParams {
  scanStatus?: RiskAssessmentStatus[];
}

/** Common assessment-details envelope shared by external scans and risk assessments. */
export interface AssessmentDetailsDTO {
  organization_name?: string;
  domain_prim?: string;
  organization_address?: Record<string, unknown>;
  contact_first_name?: string;
  contact_last_name?: string;
  contact_email?: string;
  business_phone?: string;
  annual_revenue?: number;
  employee_count?: number;
  primary_operations?: string;
  [key: string]: unknown;
}

export interface ExternalScanDTO {
  id: string;
  scanStatus: string;
  assessmentDetails: AssessmentDetailsDTO;
  securityScore: string;
  lastScannedAt?: string;
  createdAt: string;
  updatedAt: string;
  grades?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface ExternalScansDTO {
  message: string;
  assessments: ExternalScanDTO[];
  total: number;
}

export interface SecurityFindingDTO {
  name: string;
  slug?: string;
  description?: string;
  risk?: string;
  recommendation?: string;
  references?: string[];
  scanType: string;
  severity: string;
  [key: string]: unknown;
}

export interface SecurityFindingDetailDTO {
  id: string;
  domain: string;
  slug: string;
  scanType: string;
  severity: string;
  value: string;
  status: string;
  comment: string;
  devLogs: string;
  createdAt: string;
  updatedAt: string;
  [key: string]: unknown;
}

export interface BreachDataDTO {
  id: string;
  securityScanId: string;
  domainName: string;
  sourceId: string;
  breachName: string;
  lastBreach: string;
  email: string;
  ipAddress: string;
  userName: string;
  password: string;
  hashedPassword: string;
  hashType: string;
  name: string;
  address: string;
  phone: string;
  createdAt: string;
  updatedAt: string;
  [key: string]: unknown;
}

export interface RiskAssessmentDTO {
  id: string;
  telivyKey: string;
  scanStatus: string;
  assessmentDetails: AssessmentDetailsDTO;
  createdAt: string;
  updatedAt: string;
  monitoringEnabled: boolean;
  monitoringFrequency?: string;
  executiveSummary?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface RiskAssessmentsDTO {
  message: string;
  assessments: RiskAssessmentDTO[];
  total: number;
}

export interface DeepScanTargetDTO {
  id: string;
  hostname: string;
  macAddress?: string;
  osVersion?: string;
  telivyAgentInstalledAt?: string;
  telivyAgentUninstalledAt?: string;
  lastHeartBeatAt?: string;
  status: string;
  scanCompleted: boolean;
  agentVersion?: string;
  createdAt: string;
  updatedAt: string;
  [key: string]: unknown;
}

export interface DeviceScanStatusSummary {
  deviceId: string;
  hostname: string;
  status: string;
  scanCompleted: boolean;
  [key: string]: unknown;
}

export interface AssessmentScanStatusDTO {
  totalDevices: number;
  completedDevices: number;
  inProgressDevices: number;
  allScansCompleted: boolean;
  devices: DeviceScanStatusSummary[];
}

/**
 * M365/Google Workspace user-directory responses share this envelope.
 * `data` is left untyped: Telivy documents `configured`/`connectionStatus`/
 * `lastSyncedAt` at this level but describes the per-user array's shape via
 * separate M365UserDTO/GwsUserDTO schemas nested inside `data` in a way this
 * connector doesn't need to unpack field-by-field to pass through faithfully.
 */
export interface CloudUsersResponseDTO {
  message?: string;
  configured: boolean;
  connectionStatus: string;
  data: Record<string, unknown>;
  lastSyncedAt?: string;
  [key: string]: unknown;
}

export interface PiiDeviceSummaryDTO {
  hostname: string;
  filesScanned: number;
  sensitiveFiles: number;
  totalRisk: number;
  [key: string]: unknown;
}

export interface PiiSummaryDataDTO {
  distributionByType: unknown[];
  deviceSummaries: PiiDeviceSummaryDTO[];
  totalSensitiveFiles: number;
  totalDataRisk: number;
}

export interface AgentVersionsDTO {
  windows: string;
  mac: string;
}

export interface FindingWithTaskResponseDTO {
  id: string;
  timestampGroup: string;
  identifier: string;
  slug: string;
  value: string;
  valueId?: string;
  applicationId?: string;
  createdAt: string;
  updatedAt: string;
  task?: Record<string, unknown>;
  source?: string;
  decision?: Record<string, unknown>;
  cisCategory?: string;
  controlId?: string;
  [key: string]: unknown;
}

export interface ProgressReportDTO {
  new: unknown[];
  resolved: unknown[];
  regressed: unknown[];
  open: unknown[];
}

export interface FindingsProgressReportResponseDTO {
  message?: string;
  scans: Record<string, unknown>;
  report: ProgressReportDTO;
}

import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import {
  getCredentials,
  getPiiSummary,
  getRiskAssessment,
  getRiskAssessmentDevice,
  getRiskAssessmentScanStatus,
  listGwsUsers,
  listM365Users,
  listRiskAssessmentDevices,
  listRiskAssessments,
} from '../client.js';
import type { ListRiskAssessmentsParams } from '../types.js';
import type { CallToolResult } from './types.js';
import { errorResult, LIST_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const RISK_ASSESSMENT_TOOLS: Tool[] = [
  {
    name: 'telivy_list_risk_assessments',
    description: 'List risk assessments - deep-scan (agent-based) fleet security assessments, optionally filtered by scan status.',
    inputSchema: {
      type: 'object',
      properties: {
        ...LIST_PARAMS_PROPERTIES,
        scanStatus: {
          type: 'array',
          items: { type: 'string', enum: ['not_started', 'in_progress', 'report_completed', 'archived'] },
          description: 'Filter to one or more scan statuses.',
        },
      },
    },
  },
  {
    name: 'telivy_get_risk_assessment',
    description: 'Get a single risk assessment by ID.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Assessment UUID.' } },
      required: ['id'],
    },
  },
  {
    name: 'telivy_list_risk_assessment_devices',
    description: 'List all deep-scan devices for a risk assessment.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Assessment UUID.' } },
      required: ['id'],
    },
  },
  {
    name: 'telivy_get_risk_assessment_device',
    description: 'Get a single deep-scan device by ID.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Assessment UUID.' },
        deviceId: { type: 'string', description: 'Deep scan target (device) UUID.' },
      },
      required: ['id', 'deviceId'],
    },
  },
  {
    name: 'telivy_get_risk_assessment_scan_status',
    description: 'Get scan completion status across all devices in a risk assessment.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Assessment UUID.' } },
      required: ['id'],
    },
  },
  {
    name: 'telivy_list_m365_users',
    description: 'Get Microsoft 365 user accounts with login status and MFA info for a risk assessment.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Assessment UUID.' } },
      required: ['id'],
    },
  },
  {
    name: 'telivy_list_gws_users',
    description: 'Get Google Workspace user accounts with login and 2SV status for a risk assessment.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Assessment UUID.' } },
      required: ['id'],
    },
  },
  {
    name: 'telivy_get_pii_summary',
    description: 'Get the PII exposure summary across all devices in a risk assessment.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Assessment UUID.' } },
      required: ['id'],
    },
  },
];

function listParamsFromArgs(args: Record<string, unknown>): ListRiskAssessmentsParams {
  return {
    search: args.search as string | undefined,
    assessmentSortBy: args.assessmentSortBy as ListRiskAssessmentsParams['assessmentSortBy'],
    sortOrder: args.sortOrder as ListRiskAssessmentsParams['sortOrder'],
    offset: args.offset as number | undefined,
    limit: args.limit as number | undefined,
    agencyId: args.agencyId as string | undefined,
    scanStatus: args.scanStatus as ListRiskAssessmentsParams['scanStatus'],
  };
}

export async function handleRiskAssessmentTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'telivy_list_risk_assessments') {
      return textResult(await listRiskAssessments(creds!, listParamsFromArgs(args)));
    }

    if (name === 'telivy_get_risk_assessment') {
      return textResult(await getRiskAssessment(creds!, args.id as string));
    }

    if (name === 'telivy_list_risk_assessment_devices') {
      return textResult(await listRiskAssessmentDevices(creds!, args.id as string));
    }

    if (name === 'telivy_get_risk_assessment_device') {
      return textResult(await getRiskAssessmentDevice(creds!, args.id as string, args.deviceId as string));
    }

    if (name === 'telivy_get_risk_assessment_scan_status') {
      return textResult(await getRiskAssessmentScanStatus(creds!, args.id as string));
    }

    if (name === 'telivy_list_m365_users') {
      return textResult(await listM365Users(creds!, args.id as string));
    }

    if (name === 'telivy_list_gws_users') {
      return textResult(await listGwsUsers(creds!, args.id as string));
    }

    if (name === 'telivy_get_pii_summary') {
      return textResult(await getPiiSummary(creds!, args.id as string));
    }

    return errorResult(`Unknown risk assessment tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}

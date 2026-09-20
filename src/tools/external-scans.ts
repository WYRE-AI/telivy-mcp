import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import {
  getBreachData,
  getCredentials,
  getExternalScan,
  getExternalScanFinding,
  listExternalScanFindings,
  listExternalScans,
} from '../client.js';
import type { ListParams } from '../types.js';
import type { CallToolResult } from './types.js';
import { errorResult, LIST_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const EXTERNAL_SCAN_TOOLS: Tool[] = [
  {
    name: 'telivy_list_external_scans',
    description: 'List external (surface) scans - lightweight, agentless domain/email security assessments.',
    inputSchema: { type: 'object', properties: { ...LIST_PARAMS_PROPERTIES } },
  },
  {
    name: 'telivy_get_external_scan',
    description: 'Get a single external scan by assessment ID.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Assessment ID.' } },
      required: ['id'],
    },
  },
  {
    name: 'telivy_list_external_scan_findings',
    description: 'List the findings for an external scan.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Assessment ID.' } },
      required: ['id'],
    },
  },
  {
    name: 'telivy_get_external_scan_finding',
    description: 'Get details for a single external scan finding by slug.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Assessment ID.' },
        slug: { type: 'string', description: 'Finding slug.' },
      },
      required: ['id', 'slug'],
    },
  },
  {
    name: 'telivy_get_breach_data',
    description: "Get breach records surfaced for an external scan's domain(s) (dark-web/credential exposure).",
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Assessment ID.' } },
      required: ['id'],
    },
  },
];

function listParamsFromArgs(args: Record<string, unknown>): ListParams {
  return {
    search: args.search as string | undefined,
    assessmentSortBy: args.assessmentSortBy as ListParams['assessmentSortBy'],
    sortOrder: args.sortOrder as ListParams['sortOrder'],
    offset: args.offset as number | undefined,
    limit: args.limit as number | undefined,
    agencyId: args.agencyId as string | undefined,
  };
}

export async function handleExternalScanTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'telivy_list_external_scans') {
      return textResult(await listExternalScans(creds!, listParamsFromArgs(args)));
    }

    if (name === 'telivy_get_external_scan') {
      return textResult(await getExternalScan(creds!, args.id as string));
    }

    if (name === 'telivy_list_external_scan_findings') {
      return textResult(await listExternalScanFindings(creds!, args.id as string));
    }

    if (name === 'telivy_get_external_scan_finding') {
      return textResult(await getExternalScanFinding(creds!, args.id as string, args.slug as string));
    }

    if (name === 'telivy_get_breach_data') {
      return textResult(await getBreachData(creds!, args.id as string));
    }

    return errorResult(`Unknown external scan tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}

import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getAgentVersions, getCredentials, getFinding, getRiskProgress } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, requireCredentials, textResult } from './shared.js';

export const MISC_TOOLS: Tool[] = [
  {
    name: 'telivy_get_agent_versions',
    description: 'Get the latest Telivy deep-scan agent versions available (Windows and Mac).',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'telivy_get_finding',
    description: 'Get top-level finding details by slug (e.g. TYPO_SQUATTING, PERSONAL_EMAILS).',
    inputSchema: {
      type: 'object',
      properties: { slug: { type: 'string', description: 'Finding slug.' } },
      required: ['slug'],
    },
  },
  {
    name: 'telivy_get_risk_progress',
    description: 'Get a risk progress report comparing two scan timestamp groups for an assessment (new/resolved/regressed/open findings).',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Assessment UUID.' },
        currentTimestampGroup: { type: 'string', description: 'The current/most recent scan timestamp group.' },
        compareWithTimestampGroup: {
          type: 'string',
          description: 'The scan timestamp group to compare against. Defaults to the previous scan if omitted.',
        },
      },
      required: ['id', 'currentTimestampGroup'],
    },
  },
];

export async function handleMiscTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'telivy_get_agent_versions') {
      return textResult(await getAgentVersions(creds!));
    }

    if (name === 'telivy_get_finding') {
      return textResult(await getFinding(creds!, args.slug as string));
    }

    if (name === 'telivy_get_risk_progress') {
      return textResult(
        await getRiskProgress(
          creds!,
          args.id as string,
          args.currentTimestampGroup as string,
          args.compareWithTimestampGroup as string | undefined
        )
      );
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}

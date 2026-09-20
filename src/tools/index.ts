import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { EXTERNAL_SCAN_TOOLS, handleExternalScanTool } from './external-scans.js';
import { RISK_ASSESSMENT_TOOLS, handleRiskAssessmentTool } from './risk-assessments.js';
import { MISC_TOOLS, handleMiscTool } from './misc.js';
import type { CallToolResult } from './types.js';

export const ALL_TOOLS: Tool[] = [...EXTERNAL_SCAN_TOOLS, ...RISK_ASSESSMENT_TOOLS, ...MISC_TOOLS];

const EXTERNAL_SCAN_NAMES = new Set(EXTERNAL_SCAN_TOOLS.map((t) => t.name));
const RISK_ASSESSMENT_NAMES = new Set(RISK_ASSESSMENT_TOOLS.map((t) => t.name));
const MISC_NAMES = new Set(MISC_TOOLS.map((t) => t.name));

export async function dispatchToolCall(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  if (EXTERNAL_SCAN_NAMES.has(name)) return handleExternalScanTool(name, args);
  if (RISK_ASSESSMENT_NAMES.has(name)) return handleRiskAssessmentTool(name, args);
  if (MISC_NAMES.has(name)) return handleMiscTool(name, args);
  return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
}

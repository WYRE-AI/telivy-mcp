import type { TelivyCredentials } from '../types.js';
import type { CallToolResult } from './types.js';

export function textResult(value: unknown): CallToolResult {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: 'text', text }] };
}

export function errorResult(message: string): CallToolResult {
  return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
}

/** Returns an error CallToolResult if credentials are missing, else null. */
export function requireCredentials(creds: TelivyCredentials | null): CallToolResult | null {
  if (!creds) {
    return errorResult('No Telivy credentials configured. Set TELIVY_API_KEY.');
  }
  return null;
}

/** Shared input-schema fragment for the list endpoints' pagination/sort/search params. */
export const LIST_PARAMS_PROPERTIES = {
  search: { type: 'string', description: 'Free-text search query.' },
  assessmentSortBy: {
    type: 'string',
    enum: ['organizationName', 'assessmentStatus', 'createdAt', 'updatedAt'],
    description: 'Field to sort by. Defaults to createdAt.',
  },
  sortOrder: {
    type: 'string',
    enum: ['DESC', 'ASC'],
    description: 'Sort order. Defaults to DESC.',
  },
  offset: { type: 'number', description: 'Pagination offset.' },
  limit: { type: 'number', description: 'Maximum results to return. Defaults to 100.' },
  agencyId: {
    type: 'string',
    description: 'TELIVY_ADMIN-only: scope results to a specific agency (ignored by non-admin API keys).',
  },
} as const;

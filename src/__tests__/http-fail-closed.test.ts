/**
 * HTTP transport fails closed (CWE-306).
 *
 * Startup refuses to listen when CONDUIT_S2S_SECRET is empty or a known
 * placeholder, unless MCP_ALLOW_INSECURE_DEV=1. That bypass binds 127.0.0.1
 * only. Gateway-mode /mcp requests without X-Telivy-Api-Key are 401 and must
 * not fall back to TELIVY_API_KEY.
 */
import { createHmac } from 'node:crypto';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import * as clientModule from '../client.js';
import { startHttpServer } from '../http.js';
import { jsonResponse } from './test-helpers.js';

const TEST_SECRET = 'test-s2s-fail-closed-secret-do-not-use-in-prod';
const ENV_API_KEY = 'env-telivy-key-must-not-be-used';
const HEADER_API_KEY = 'header-telivy-key-from-request';

const ENV_KEYS = [
  'MCP_TRANSPORT',
  'AUTH_MODE',
  'MCP_HTTP_PORT',
  'MCP_HTTP_HOST',
  'CONDUIT_S2S_SECRET',
  'MCP_ALLOW_INSECURE_DEV',
  'TELIVY_API_KEY',
  'LOG_LEVEL',
] as const;

const originalEnv = new Map<string, string | undefined>();
const servers: Server[] = [];

function mintS2sHeader(secret: string, unixSeconds = Math.floor(Date.now() / 1000)): string {
  const message = `t=${unixSeconds}`;
  const hex = createHmac('sha256', secret).update(message).digest('hex');
  return `${message},v1=${hex}`;
}

function captureConsoleError(): { text: () => string; restore: () => void } {
  const lines: string[] = [];
  const spy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    lines.push(args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  });
  return {
    text: () => lines.join('\n'),
    restore: () => spy.mockRestore(),
  };
}

function exitSpy() {
  return vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new Error(`process.exit:${String(code)}`);
  }) as typeof process.exit);
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

async function listen(): Promise<{ server: Server; port: number; address: string }> {
  const server = await startHttpServer();
  servers.push(server);
  const bound = server.address() as AddressInfo | string | null;
  if (!bound || typeof bound === 'string') {
    throw new Error('HTTP server did not bind a TCP port');
  }
  return { server, port: bound.port, address: bound.address };
}

function mcpHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    ...extra,
  };
}

const agentVersionsCall = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/call',
  params: { name: 'telivy_get_agent_versions', arguments: {} },
});

beforeAll(() => {
  for (const key of ENV_KEYS) originalEnv.set(key, process.env[key]);
});

afterAll(() => {
  for (const key of ENV_KEYS) {
    const value = originalEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

beforeEach(() => {
  process.env.MCP_HTTP_PORT = '0';
  process.env.MCP_HTTP_HOST = '127.0.0.1';
  process.env.LOG_LEVEL = 'error';
  delete process.env.CONDUIT_S2S_SECRET;
  delete process.env.MCP_ALLOW_INSECURE_DEV;
  delete process.env.AUTH_MODE;
  delete process.env.TELIVY_API_KEY;
  delete process.env.MCP_TRANSPORT;
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  while (servers.length > 0) {
    const server = servers.pop();
    if (server) await closeServer(server);
  }
});

describe('HTTP startup fails closed without CONDUIT_S2S_SECRET', () => {
  it('logs an error and exits non-zero when the secret is empty', () => {
    const logs = captureConsoleError();
    const exit = exitSpy();
    try {
      expect(() => startHttpServer()).toThrow('process.exit:1');
      expect(exit).toHaveBeenCalledWith(1);
      const logged = logs.text();
      expect(logged).toContain('Refusing to start HTTP server: CONDUIT_S2S_SECRET is empty.');
      expect(logged).toContain('MCP_ALLOW_INSECURE_DEV=1');
      expect(logged).not.toContain(TEST_SECRET);
    } finally {
      logs.restore();
      exit.mockRestore();
    }
  });

  it('still exits when MCP_ALLOW_INSECURE_DEV is not exactly 1', () => {
    process.env.MCP_ALLOW_INSECURE_DEV = 'true';
    const logs = captureConsoleError();
    const exit = exitSpy();
    try {
      expect(() => startHttpServer()).toThrow('process.exit:1');
      expect(exit).toHaveBeenCalledWith(1);
      expect(logs.text()).toContain('Refusing to start HTTP server: CONDUIT_S2S_SECRET is empty.');
    } finally {
      logs.restore();
      exit.mockRestore();
    }
  });

  it('treats a whitespace-only secret as empty', () => {
    process.env.CONDUIT_S2S_SECRET = '   ';
    const logs = captureConsoleError();
    const exit = exitSpy();
    try {
      expect(() => startHttpServer()).toThrow('process.exit:1');
      expect(logs.text()).toContain('CONDUIT_S2S_SECRET is empty');
    } finally {
      logs.restore();
      exit.mockRestore();
    }
  });

  it('starts and logs a warning when MCP_ALLOW_INSECURE_DEV=1 and binds 127.0.0.1', async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    delete process.env.MCP_HTTP_HOST;
    const logs = captureConsoleError();
    const exit = exitSpy();
    try {
      const server = await listen();
      expect(exit).not.toHaveBeenCalled();
      expect(server.address).toBe('127.0.0.1');
      const logged = logs.text();
      expect(logged).toContain('SECURITY WARNING');
      expect(logged).toContain('MCP_ALLOW_INSECURE_DEV=1');
      expect(logged).toContain('DISABLED');
      expect(logged).toContain('127.0.0.1');
      expect(logged).not.toContain(TEST_SECRET);
    } finally {
      logs.restore();
      exit.mockRestore();
    }
  });

  it('refuses a known placeholder secret and does not log it', () => {
    process.env.CONDUIT_S2S_SECRET = 'replace-with-a-real-secret';
    const logs = captureConsoleError();
    const exit = exitSpy();
    try {
      expect(() => startHttpServer()).toThrow('process.exit:1');
      expect(exit).toHaveBeenCalledWith(1);
      const logged = logs.text();
      expect(logged).toContain('known placeholder');
      expect(logged).toContain('openssl rand -hex 32');
      expect(logged).not.toContain('replace-with-a-real-secret');
    } finally {
      logs.restore();
      exit.mockRestore();
    }
  });

  it.each(['changeme', 'your-s2s-secret', 'CHANGE-ME', 'example'])(
    'refuses the placeholder %s',
    (placeholder) => {
      process.env.CONDUIT_S2S_SECRET = placeholder;
      const logs = captureConsoleError();
      const exit = exitSpy();
      try {
        expect(() => startHttpServer()).toThrow('process.exit:1');
        expect(logs.text()).toContain('known placeholder');
        expect(logs.text()).not.toContain(placeholder);
      } finally {
        logs.restore();
        exit.mockRestore();
      }
    },
  );

  it('refuses a placeholder even when MCP_ALLOW_INSECURE_DEV=1', () => {
    process.env.CONDUIT_S2S_SECRET = '  Your-S2S-Secret  ';
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    const logs = captureConsoleError();
    const exit = exitSpy();
    try {
      expect(() => startHttpServer()).toThrow('process.exit:1');
      expect(exit).toHaveBeenCalledWith(1);
      expect(logs.text()).not.toContain('Your-S2S-Secret');
    } finally {
      logs.restore();
      exit.mockRestore();
    }
  });

  it('forces 127.0.0.1 when insecure dev is set and the host is loopback', async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    process.env.MCP_HTTP_HOST = 'localhost';
    process.env.LOG_LEVEL = 'info';
    const logs = captureConsoleError();
    const exit = exitSpy();
    try {
      const server = await listen();
      expect(exit).not.toHaveBeenCalled();
      expect(server.address).toBe('127.0.0.1');
      expect(logs.text()).toContain(`HTTP streaming server listening on 127.0.0.1:${server.port}`);
      expect(logs.text()).not.toContain('listening on localhost');
    } finally {
      logs.restore();
      exit.mockRestore();
    }
  });

  it.each(['0.0.0.0', '10.1.2.3'])(
    'refuses insecure dev when MCP_HTTP_HOST is %s',
    (host) => {
      process.env.MCP_ALLOW_INSECURE_DEV = '1';
      process.env.MCP_HTTP_HOST = host;
      const logs = captureConsoleError();
      const exit = exitSpy();
      try {
        expect(() => startHttpServer()).toThrow('process.exit:1');
        expect(exit).toHaveBeenCalledWith(1);
        const logged = logs.text();
        expect(logged).toContain('only binds 127.0.0.1');
        expect(logged).not.toContain(TEST_SECRET);
      } finally {
        logs.restore();
        exit.mockRestore();
      }
    },
  );

  it('still honors a non-loopback host when a real secret is set', async () => {
    process.env.CONDUIT_S2S_SECRET = TEST_SECRET;
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    process.env.LOG_LEVEL = 'info';
    const logs = captureConsoleError();
    const exit = exitSpy();
    try {
      const server = await listen();
      expect(exit).not.toHaveBeenCalled();
      expect(server.address).toBe('0.0.0.0');
      const logged = logs.text();
      expect(logged).toContain(`HTTP streaming server listening on 0.0.0.0:${server.port}`);
      expect(logged).not.toContain(TEST_SECRET);
    } finally {
      logs.restore();
      exit.mockRestore();
    }
  });

  it('binds 127.0.0.1 when a secret is set and MCP_HTTP_HOST is unset', async () => {
    process.env.CONDUIT_S2S_SECRET = TEST_SECRET;
    delete process.env.MCP_HTTP_HOST;
    const server = await listen();
    expect(server.address).toBe('127.0.0.1');
  });
});

describe('gateway /mcp auth', () => {
  let port = 0;
  let getCredentialsSpy: ReturnType<typeof vi.spyOn>;
  const realFetch = globalThis.fetch.bind(globalThis);
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (url.startsWith('https://api-v1.telivy.com')) {
      return jsonResponse({ windows: '1.2.3', mac: '1.2.3' });
    }
    return realFetch(input, init);
  });

  function telivyApiCalls(): Array<[RequestInfo | URL, RequestInit | undefined]> {
    return fetchMock.mock.calls.filter((call) => {
      const input = call[0];
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      return url.startsWith('https://api-v1.telivy.com');
    }) as Array<[RequestInfo | URL, RequestInit | undefined]>;
  }

  beforeEach(async () => {
    process.env.CONDUIT_S2S_SECRET = TEST_SECRET;
    process.env.AUTH_MODE = 'gateway';
    process.env.TELIVY_API_KEY = ENV_API_KEY;
    delete process.env.MCP_HTTP_HOST;
    process.env.LOG_LEVEL = 'info';
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockClear();
    getCredentialsSpy = vi.spyOn(clientModule, 'getCredentials');
    const logs = captureConsoleError();
    try {
      const server = await listen();
      port = server.port;
      expect(server.address).toBe('127.0.0.1');
      expect(logs.text()).not.toContain(TEST_SECRET);
      expect(logs.text()).not.toContain(ENV_API_KEY);
    } finally {
      logs.restore();
    }
    getCredentialsSpy.mockClear();
    fetchMock.mockClear();
  });

  async function postMcp(headers: Record<string, string>): Promise<Response> {
    return fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: mcpHeaders(headers),
      body: agentVersionsCall,
    });
  }

  it('serves /health and /healthz without reading credentials', async () => {
    for (const path of ['/health', '/healthz']) {
      const res = await fetch(`http://127.0.0.1:${port}${path}`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as { status?: string; credentials?: unknown; mode?: string };
      expect(body.status).toBe('ok');
      expect(body.credentials).toBeUndefined();
      expect(body.mode).toBe('gateway');
      expect(JSON.stringify(body)).not.toContain(ENV_API_KEY);
      expect(JSON.stringify(body)).not.toContain(TEST_SECRET);
    }
    expect(getCredentialsSpy).not.toHaveBeenCalled();
    expect(telivyApiCalls()).toHaveLength(0);
  });

  it('returns 401 when the S2S header is missing or invalid and does not read credentials', async () => {
    const missing = await postMcp({ 'x-telivy-api-key': HEADER_API_KEY });
    const invalid = await postMcp({
      'x-gateway-s2s': mintS2sHeader('wrong-secret'),
      'x-telivy-api-key': HEADER_API_KEY,
    });

    expect(missing.status).toBe(401);
    expect(invalid.status).toBe(401);
    const missingBody = (await missing.json()) as { error: string };
    const invalidBody = (await invalid.json()) as { error: string };
    expect(missingBody.error).toContain('X-Gateway-S2S');
    expect(invalidBody.error).toContain('X-Gateway-S2S');
    expect(JSON.stringify(missingBody)).not.toContain(ENV_API_KEY);
    expect(JSON.stringify(missingBody)).not.toContain(TEST_SECRET);
    expect(JSON.stringify(invalidBody)).not.toContain(HEADER_API_KEY);
    expect(getCredentialsSpy).not.toHaveBeenCalled();
    expect(telivyApiCalls()).toHaveLength(0);
  });

  it('returns 401 in gateway mode when the credential header is missing and does not use env credentials', async () => {
    const response = await postMcp({ 'x-gateway-s2s': mintS2sHeader(TEST_SECRET) });
    const body = (await response.json()) as { error: string };

    expect(response.status).toBe(401);
    expect(body.error).toContain('X-Telivy-Api-Key');
    expect(JSON.stringify(body)).not.toContain(ENV_API_KEY);
    expect(JSON.stringify(body)).not.toContain(TEST_SECRET);
    expect(getCredentialsSpy).not.toHaveBeenCalled();
    expect(telivyApiCalls()).toHaveLength(0);

    const blank = await postMcp({
      'x-gateway-s2s': mintS2sHeader(TEST_SECRET),
      'x-telivy-api-key': '   ',
    });
    expect(blank.status).toBe(401);
    expect(getCredentialsSpy).not.toHaveBeenCalled();
    expect(telivyApiCalls()).toHaveLength(0);
  });

  it('accepts a valid S2S header plus X-Telivy-Api-Key and uses that key', async () => {
    const response = await postMcp({
      'x-gateway-s2s': mintS2sHeader(TEST_SECRET),
      'x-telivy-api-key': HEADER_API_KEY,
    });
    const body = (await response.json()) as { result?: { content?: Array<{ text?: string }> } };
    const text = body.result?.content?.[0]?.text ?? '';

    expect(response.status).toBe(200);
    expect(text).toContain('1.2.3');
    expect(JSON.stringify(body)).not.toContain(ENV_API_KEY);
    expect(JSON.stringify(body)).not.toContain(TEST_SECRET);
    const apiCalls = telivyApiCalls();
    expect(apiCalls).toHaveLength(1);
    const headers = apiCalls[0][1]?.headers as Record<string, string>;
    expect(headers['x-api-key']).toBe(HEADER_API_KEY);
    expect(getCredentialsSpy).toHaveBeenCalled();
  });
});

describe('env mode still uses TELIVY_API_KEY after S2S auth', () => {
  it('does not require X-Telivy-Api-Key when AUTH_MODE is not gateway', async () => {
    process.env.CONDUIT_S2S_SECRET = TEST_SECRET;
    process.env.AUTH_MODE = 'env';
    process.env.TELIVY_API_KEY = ENV_API_KEY;
    delete process.env.MCP_HTTP_HOST;
    const realFetch = globalThis.fetch.bind(globalThis);
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (url.startsWith('https://api-v1.telivy.com')) {
        return jsonResponse({ windows: '9.9.9', mac: '9.9.9' });
      }
      return realFetch(input, init);
    });
    vi.stubGlobal('fetch', fetchMock);
    const server = await listen();

    const response = await fetch(`http://127.0.0.1:${server.port}/mcp`, {
      method: 'POST',
      headers: mcpHeaders({ 'x-gateway-s2s': mintS2sHeader(TEST_SECRET) }),
      body: agentVersionsCall,
    });
    const body = (await response.json()) as { result?: { content?: Array<{ text?: string }> } };

    expect(response.status).toBe(200);
    expect(body.result?.content?.[0]?.text ?? '').toContain('9.9.9');
    const apiCall = fetchMock.mock.calls.find((call) => {
      const input = call[0];
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      return url.startsWith('https://api-v1.telivy.com');
    });
    const headers = apiCall?.[1]?.headers as Record<string, string>;
    expect(headers['x-api-key']).toBe(ENV_API_KEY);
  });
});

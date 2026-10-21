# Telivy MCP Server

MCP server for [Telivy](https://www.telivy.com/)'s security assessment API for MSPs - external (surface) scans, deep-scan risk assessments, device inventory, M365/Google Workspace user exposure, PII summaries, and finding-level detail, for AI assistants and the WYRE Conduit gateway.

## Authentication

Telivy authenticates with a single static API key, generated from the Telivy Portal (Account > Integrations). An OAuth2/Auth0 implicit flow also exists, but the API-key path is simpler and is what MSP integrations use, so that's what this connector uses. The key is sent as the `x-api-key` HTTP header.

## Configuration

Copy [`.env.example`](.env.example) and set the variables below. Leave `CONDUIT_S2S_SECRET` empty in the example; generate a real value with `openssl rand -hex 32`.

| Env var | Description |
|---|---|
| `TELIVY_API_KEY` | API key issued by Telivy. Required for stdio and for HTTP when `AUTH_MODE=env`. Gateway mode does not read it. |
| `MCP_TRANSPORT` | `stdio` (default) or `http`. |
| `AUTH_MODE` | `env` (default outside Docker; reads `TELIVY_API_KEY`) or `gateway` (credential arrives per-request via `X-Telivy-Api-Key`). The image and Compose file default to `gateway`. Gateway mode returns 401 when that header is missing and never falls back to `TELIVY_API_KEY`. |
| `CONDUIT_S2S_SECRET` | Required for HTTP. HMAC secret checked against `X-Gateway-S2S` on `/mcp`. If it is empty or a known placeholder (`changeme`, `secret`, `your-s2s-secret`, and the other example values in `src/http.ts`), the process logs an error and exits non-zero. The value is never logged. Compose will not start when it is unset. |
| `MCP_ALLOW_INSECURE_DEV` | Set to exactly `1` to start HTTP without `CONDUIT_S2S_SECRET`. Logs a warning, does not enforce `X-Gateway-S2S`, and binds `127.0.0.1` only. A non-loopback `MCP_HTTP_HOST` (including `0.0.0.0`) refuses to start. A known placeholder secret is still refused. Local development only. |
| `MCP_HTTP_HOST` | Bind address when `MCP_TRANSPORT=http`. Defaults to `127.0.0.1`. A configured secret keeps honoring this value, including `0.0.0.0`. The container image sets `0.0.0.0`. With no secret, the insecure-dev bypass forces `127.0.0.1`. |
| `MCP_HTTP_PORT` | HTTP port. Defaults to `8080`. |
| `LOG_LEVEL` | `debug` \| `info` (default) \| `warn` \| `error`. |

`/health` and `/healthz` stay unauthenticated and do not read credentials. The stdio transport does not use `CONDUIT_S2S_SECRET`.

### HTTP authentication

With `MCP_TRANSPORT=http` and `CONDUIT_S2S_SECRET` set, every `/mcp` request must include `X-Gateway-S2S`. The check is `verifyS2sHeader` in [`src/s2s-verify.ts`](src/s2s-verify.ts): the header value is `t=<unix seconds>,v1=<hex>`, where the hex is HMAC-SHA256 of the literal string `t=<unix seconds>` keyed with `CONDUIT_S2S_SECRET` (64 lowercase hex characters). The timestamp must be within 300 seconds of the server clock. A missing or invalid header is HTTP 401, before the Telivy API key is read.

```bash
TS=$(date +%s)
SIG=$(printf 't=%s' "$TS" | openssl dgst -sha256 -hmac "$CONDUIT_S2S_SECRET" -hex | awk '{print $NF}')
curl -sS http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H "X-Gateway-S2S: t=${TS},v1=${SIG}" \
  -H "X-Telivy-Api-Key: $TELIVY_API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

In `AUTH_MODE=gateway`, `/mcp` also requires `X-Telivy-Api-Key`. That header is the only credential source for the request. `AUTH_MODE=env` still requires a valid `X-Gateway-S2S` header, then uses `TELIVY_API_KEY` from the environment.

### Request limits

- HTTP request bodies are capped at 256 KiB (262144 bytes). After the `X-Gateway-S2S` check (and, in `AUTH_MODE=gateway`, the `X-Telivy-Api-Key` presence check) passes, a `Content-Length` above the cap returns 413 with a JSON-RPC error; bodies without `Content-Length` are capped by the MCP SDK transport. Unauthenticated requests still get 401 first.
- `tools/call` arguments are capped at 10,000 elements (every array item and object key at any depth). Larger inputs return an `isError` tool result and are never dispatched.

These limits address CVE-2026-111768 / GHSA-46jr-4wx8-v453 (memory exhaustion during validation) and GHSA-f897-62hf-6gxq (no request body / batch cap).

## Tools

### External scans
- `telivy_list_external_scans` - list external (surface) scans, with search/sort/pagination.
- `telivy_get_external_scan` - get a single external scan by assessment ID.
- `telivy_list_external_scan_findings` - list the findings for an external scan.
- `telivy_get_external_scan_finding` - get details for a single external scan finding by slug.
- `telivy_get_breach_data` - get breach records surfaced for an external scan's domain(s).

### Risk assessments
- `telivy_list_risk_assessments` - list deep-scan risk assessments, with search/sort/pagination/status filters.
- `telivy_get_risk_assessment` - get a single risk assessment by ID.
- `telivy_list_risk_assessment_devices` - list all deep-scan devices for a risk assessment.
- `telivy_get_risk_assessment_device` - get a single deep-scan device by ID.
- `telivy_get_risk_assessment_scan_status` - get scan completion status across all devices.
- `telivy_list_m365_users` - get Microsoft 365 user accounts with login status and MFA info.
- `telivy_list_gws_users` - get Google Workspace user accounts with login and 2SV status.
- `telivy_get_pii_summary` - get the PII exposure summary across all devices.

### Findings, agent versions, and risk progress
- `telivy_get_agent_versions` - get the latest deep-scan agent versions (Windows/Mac).
- `telivy_get_finding` - get top-level finding details by slug (e.g. `TYPO_SQUATTING`, `PERSONAL_EMAILS`).
- `telivy_get_risk_progress` - get a progress report (new/resolved/regressed/open findings) comparing two scan timestamp groups.

## Scope

This is a v1, read-only MSP fleet/security-visibility surface, matching this wave's convention of scoping connectors to monitoring/visibility and deferring provisioning-style writes. Explicitly out of scope for now:

- All write endpoints: creating or updating external scans and risk assessments, `rescan-all`, `uninstall-all`, rescanning a single device, `convert-to-risk-assessment`, and updating monitoring settings. These are provisioning/destructive actions, not read-only visibility.
- The binary report-download endpoints (`GET .../external-scans/{id}/report`, `GET .../risk-assessments/{id}/report`) - they return files, not the structured JSON this connector's tools deal in.
- `GET /api/v1/security/risk-assessments/{id}/domain-change-preview` - a preview endpoint for an in-flight domain-change write, out of scope alongside the write it previews.

They can be added as a follow-up if there's demand.

## Development

```bash
npm install
npm run build
npm test
npm run lint   # tsc --noEmit
```

HTTP refuses to start until `CONDUIT_S2S_SECRET` is set:

```bash
CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" npm run start:http
```

Local HTTP without a service-to-service secret binds `127.0.0.1` only and logs a warning. The image sets `MCP_HTTP_HOST=0.0.0.0`, so this bypass also requires that variable to be loopback (or unset). A non-loopback host makes startup exit:

```bash
MCP_ALLOW_INSECURE_DEV=1 npm run start:http
```

## Docker

The image listens on `0.0.0.0` inside the container and defaults to `AUTH_MODE=gateway`. Publish the port on loopback and pass a real S2S secret. In gateway mode the Telivy API key arrives on each request as `X-Telivy-Api-Key`; it is not read from the environment.

```bash
docker build -t telivy-mcp .
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -p 127.0.0.1:8080:8080 \
  telivy-mcp
```

Compose refuses to start when `CONDUIT_S2S_SECRET` is unset or empty, defaults `AUTH_MODE` to `gateway`, publishes `127.0.0.1:8080:8080`, and does not set `TELIVY_API_KEY`:

```bash
CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" docker compose up
```

Single-tenant HTTP (`AUTH_MODE=env`) still requires the S2S secret, then uses `TELIVY_API_KEY`:

```bash
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -e AUTH_MODE=env \
  -e TELIVY_API_KEY="$TELIVY_API_KEY" \
  -p 127.0.0.1:8080:8080 \
  telivy-mcp
```

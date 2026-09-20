# Telivy MCP Server

MCP server for [Telivy](https://www.telivy.com/)'s security assessment API for MSPs - external (surface) scans, deep-scan risk assessments, device inventory, M365/Google Workspace user exposure, PII summaries, and finding-level detail, for AI assistants and the WYRE Conduit gateway.

## Authentication

Telivy authenticates with a single static API key, generated from the Telivy Portal (Account > Integrations). An OAuth2/Auth0 implicit flow also exists, but the API-key path is simpler and is what MSP integrations use, so that's what this connector uses. The key is sent as the `x-api-key` HTTP header.

## Configuration

| Env var | Description |
|---|---|
| `TELIVY_API_KEY` | API key issued by Telivy. |
| `MCP_TRANSPORT` | `stdio` (default) or `http`. |
| `AUTH_MODE` | `env` (default, reads the var above) or `gateway` (credential arrives per-request via the `X-Telivy-Api-Key` header, injected by the Conduit gateway). |
| `CONDUIT_S2S_SECRET` | When set, the HTTP transport requires a valid `X-Gateway-S2S` header (Conduit sidecar auth) on every `/mcp` request. |
| `LOG_LEVEL` | `debug` \| `info` (default) \| `warn` \| `error`. |

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

## Docker

```bash
docker build -t telivy-mcp .
docker run -p 8080:8080 -e TELIVY_API_KEY=... telivy-mcp
```

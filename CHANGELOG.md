# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The HTTP transport no longer exits on a malformed request (WYREAI-741).** The request
  target was parsed against the client-supplied `Host` header, and a value that does not parse
  (or a target such as `//`) threw inside the request listener before authentication. The
  target is now parsed against a fixed base, so `Host` is no longer consulted, and a target
  that still cannot be parsed gets a `400` JSON response while the server keeps running.

### Added
- Initial release: MCP server for Telivy's security assessment API for MSPs.
- External scan tools: `telivy_list_external_scans`, `telivy_get_external_scan`, `telivy_list_external_scan_findings`, `telivy_get_external_scan_finding`, `telivy_get_breach_data`.
- Risk assessment tools: `telivy_list_risk_assessments`, `telivy_get_risk_assessment`, `telivy_list_risk_assessment_devices`, `telivy_get_risk_assessment_device`, `telivy_get_risk_assessment_scan_status`, `telivy_list_m365_users`, `telivy_list_gws_users`, `telivy_get_pii_summary`.
- Other tools: `telivy_get_agent_versions`, `telivy_get_finding`, `telivy_get_risk_progress`.

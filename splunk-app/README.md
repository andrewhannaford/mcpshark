# mcpshark Splunk App

Splunk Technology Add-On (TA) and dashboards for mcpshark MCP security events.

## Installation

1. Copy the `mcpshark/` directory into `$SPLUNK_HOME/etc/apps/`.
2. Restart Splunk (or reload the app from the UI).
3. Configure a data input pointing at your mcpshark output file (see `inputs.conf.example`).

### inputs.conf.example

```ini
[monitor:///var/log/mcpshark/*.jsonl]
sourcetype = mcpshark
index = main
```

Or pipe directly from mcpshark:

```sh
mcpshark run --output - -- npx -y @modelcontextprotocol/server-filesystem /tmp 2>> /var/log/mcpshark/events.jsonl
```

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **Overview** | Session volume, traffic timeline, top methods, server summary, recent events |
| **Detections** | Alert counts by severity, MITRE ATT&CK/ATLAS coverage heatmap, rule summary, session drill-down |

## Lookups

| File | Purpose |
|------|---------|
| `mcpshark_severity.csv` | Maps severity strings to numeric levels and display colors |
| `mcpshark_rules.csv` | Maps rule IDs to human-readable names, ATLAS/ATT&CK IDs, and descriptions |

## Field Reference

All fields are extracted from the OCSF JSON-L events emitted by mcpshark.

| Field | Source | Description |
|-------|--------|-------------|
| `mcp_server_name` | `mcp.server_name` | Server display name |
| `mcp_server_sha256` | `mcp.server_identity_sha256` | SHA-256 hash of server binary |
| `mcp_direction` | `mcp.direction` | `c2s` or `s2c` |
| `mcp_method` | `mcp.method` | JSON-RPC method (e.g., `tools/call`) |
| `mcp_tool_name` | `mcp.tool_name` | Tool name for `tools/call` events |
| `mcp_outcome` | `mcp.outcome` | `success`, `error`, or empty |
| `mcp_session_id` | `session.id` | Session UUID |
| `mcp_protocol_version` | `session.mcp_protocol_version` | MCP protocol version string |
| `mcp_host` | `host.name` | Hostname running mcpshark |
| `mcp_user` | `user.name` | OS user running mcpshark |
| `mcp_params_sha256` | `payload.params_sha256` | SHA-256 of request params |
| `mcp_params_size_bytes` | `payload.params_size_bytes` | Size of request params |
| `detection_rule_id` | `detections[0].rule_id` | Detection rule identifier |
| `detection_severity` | `detections[0].severity` | `critical`, `high`, `medium`, `low`, `info` |
| `detection_confidence` | `detections[0].confidence` | 0.0–1.0 confidence score |
| `detection_atlas` | `detections[0].atlas` | MITRE ATLAS technique ID |
| `detection_attck` | `detections[0].attck` | MITRE ATT&CK technique ID |

## CIM Compatibility

The following Common Information Model (CIM) fields are mapped for compatibility with Splunk Enterprise Security and other Technology Add-Ons:

| CIM Field | Source |
|-----------|--------|
| `src_host` | `host.name` |
| `user` | `user.name` |
| `action` | `mcp.outcome` |
| `app` | `mcp.server_name` |

# mcpshark OCSF Event Schema

mcpshark emits one JSON-L event per JSON-RPC message. Events follow [OCSF](https://schema.ocsf.io/) Application Activity (class 6003) with MCP-specific extensions.

## Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `ts` | RFC3339Nano | Event timestamp |
| `ocsf` | object | OCSF classification metadata |
| `host` | object | Host where mcpshark is running |
| `user` | object | OS user running mcpshark |
| `session` | object | MCP session context |
| `mcp` | object | MCP protocol fields |
| `payload` | object | Request parameter metadata |
| `detections` | array | Detection results (empty if no detections fired) |

## `ocsf` Object

| Field | Value | Description |
|-------|-------|-------------|
| `class_uid` | 6003 | OCSF Application Activity |
| `category_uid` | 6 | Application Activity category |
| `type_uid` | 600301 | Application Activity — Create |
| `severity_id` | 1–5 | Highest detection severity (0 if no detections) |
| `version` | 1.1.0 | OCSF schema version |

## `mcp` Object

| Field | Type | Description |
|-------|------|-------------|
| `server_name` | string | Server display name (from CLI args) |
| `server_identity_sha256` | string | SHA-256 of server executable |
| `direction` | `c2s` \| `s2c` | Message direction |
| `method` | string | JSON-RPC method (empty for responses) |
| `tool_name` | string | Tool name (for `tools/call` only) |
| `resource_uri` | string | Resource URI (for `resources/read` only) |
| `transport` | `stdio` | Transport type |
| `outcome` | `success` \| `error` \| `` | Result outcome (responses only) |

## `session` Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Session identifier (assigned by mcpshark per proxy run) |
| `mcp_protocol_version` | string | Negotiated MCP protocol version |

## `payload` Object

| Field | Type | Description |
|-------|------|-------------|
| `params_sha256` | string | SHA-256 hex of `params` field |
| `params_size_bytes` | int | Byte length of `params` field |
| `params_redacted` | string | Raw params (only in `full` or 1% sampled `sampled` mode) |

## `detections` Array

Each element represents one fired detection rule.

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | string | Unique rule identifier (e.g., `mcp.injection.ignore_instructions`) |
| `name` | string | Human-readable rule name |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | float | 0.0–1.0 confidence score |
| `detail` | string | Contextual explanation |
| `atlas` | string | MITRE ATLAS technique ID |
| `attck` | string | MITRE ATT&CK technique ID |

## Example Event

```json
{
  "ts": "2026-05-24T10:23:01.123456789Z",
  "ocsf": {
    "class_uid": 6003,
    "category_uid": 6,
    "type_uid": 600301,
    "severity_id": 4,
    "version": "1.1.0"
  },
  "host": { "name": "andrews-mac" },
  "user": { "name": "andrew" },
  "session": {
    "id": "a1b2c3d4-...",
    "mcp_protocol_version": "2024-11-05"
  },
  "mcp": {
    "server_name": "filesystem",
    "server_identity_sha256": "e3b0c44298fc...",
    "direction": "s2c",
    "method": "sampling/createMessage",
    "transport": "stdio"
  },
  "payload": {
    "params_sha256": "9f86d081884c...",
    "params_size_bytes": 312
  },
  "detections": [
    {
      "rule_id": "mcp.sampling.create",
      "name": "Sampling Request Detected",
      "severity": "high",
      "confidence": 0.95,
      "detail": "Server sent sampling/createMessage - review for prompt injection",
      "atlas": "AML.T0051",
      "attck": "T1059"
    },
    {
      "rule_id": "mcp.injection.ignore_instructions",
      "name": "Prompt Injection - Ignore Instructions",
      "severity": "high",
      "confidence": 0.90,
      "detail": "Jailbreak pattern matched: 'ignore previous instructions'",
      "atlas": "AML.T0051",
      "attck": "T1059"
    }
  ]
}
```

## Redaction Modes

Control how `payload.params_redacted` is populated:

| Mode | `--redact` flag | Behavior |
|------|----------------|---------|
| `reference_only` (default) | `reference_only` | Only SHA-256 + size; raw params never stored |
| `sampled` | `sampled` | Raw params stored for 1% of events (random sampling) |
| `full` | `full` | Raw params always stored; for local/dev use only |

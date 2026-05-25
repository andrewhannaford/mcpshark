# mcpshark

**Wireshark for the AI tool layer.**

mcpshark is a transparent security proxy for [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) servers. Drop it in front of any MCP server — Claude Desktop, Cursor, Cline — and it captures every JSON-RPC message, detects attacks in real time, and emits OCSF-aligned JSON-L for your SIEM.

No config changes to your AI client beyond swapping the command. One binary. Works today.

```
  AI Client  ──► mcpshark ──► MCP Server
                  │
             JSON-L events → Splunk / Elastic / jq
```

---

## Why this exists

MCP servers run with your AI client's trust and your API tokens. They can:

- **Drive your LLM without your knowledge** via `sampling/createMessage`
- **Phish you for credentials** via `elicitation/create`
- **Change their own tool descriptions** after initial trust is established (rug-pull / tool poisoning)
- **Enumerate your filesystem** via `roots/list`
- **Inject instructions** hidden inside tool descriptions the LLM reads but you never see

Existing tools catch some of this statically. mcpshark catches it _at runtime_, while your agent is running.

---

## What it detects

| Detection | Rule ID | Severity | MITRE |
|-----------|---------|----------|-------|
| Server-initiated LLM execution | `mcp.sampling.create` | **HIGH** | AML.T0054 / T1059 |
| Tool description changed mid-session | `mcp.tools.drift` | **HIGH** | AML.T0054 / T1195 |
| Prompt injection: ignore instructions | `mcp.injection.ignore_instructions` | **HIGH** | AML.T0051 |
| Credential file exfiltration target | `mcp.injection.file_exfil_target` | **HIGH** | AML.T0051 |
| Explicit exfiltration directive | `mcp.injection.exfiltration` | **HIGH** | AML.T0051 |
| Verbatim output directive | `mcp.injection.verbatim_response` | **HIGH** | AML.T0051 |
| Override system instructions | `mcp.injection.override_instructions` | **HIGH** | AML.T0051 |
| Server requested user data input | `mcp.elicitation.create` | MEDIUM | T1056 |
| Persona override in prompt | `mcp.injection.persona_override` | MEDIUM | AML.T0051 |
| Server queried filesystem roots | `mcp.roots.list` | LOW | T1083 |
| Server log notification (leakage) | `mcp.notification.message` | INFO | T1552 |

All detections ship with MITRE ATLAS and ATT&CK IDs. All events are OCSF Application Activity (class 6003).

---

## Quick start

```bash
# Install (Homebrew tap coming soon)
go install github.com/andrewhannaford/mcpshark/cmd/mcpshark@latest

# Wrap any MCP server — transparent passthrough with detection
mcpshark run --name my-server -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Events stream to stderr by default (pipe-safe — stdout carries clean MCP protocol)
# Write to a file instead:
mcpshark run --name my-server --output events.jsonl -- ./my-mcp-server
tail -f events.jsonl | jq 'select(.detections)'
```

### Claude Desktop integration

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```jsonc
// Before
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}

// After — mcpshark wraps the server transparently
{
  "mcpServers": {
    "filesystem": {
      "command": "mcpshark",
      "args": ["run", "--name", "filesystem", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

---

## Demo: the rug-pull attack

The repo ships with `corpus/traces/drifting-server` — a server that serves a benign tool description on the first `tools/list` call, then replaces it with a prompt injection payload on the second call (after the client has already established trust).

```bash
# Build the demo servers
go build ./corpus/...

# Feed the conversation through mcpshark
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}' \
  | mcpshark run --name rug-pull --output events.jsonl -- ./drifting-server

# Inspect the drift detection
cat events.jsonl | jq 'select(.detections[].rule_id == "mcp.tools.drift")'
```

Expected detection event includes:
```json
{
  "rule_id": "mcp.tools.drift",
  "name": "MCP tools/list fingerprint changed (tool poisoning / rug-pull)",
  "severity": "high",
  "confidence": 0.9,
  "detail": "Previous fingerprint: 281a3fbb007b683f. New fingerprint: 8d475f304c5ae20c."
}
```

---

## Event schema (OCSF class 6003)

Every MCP message produces one JSON-L event:

```json
{
  "schema_version": "1.0.0",
  "ocsf": { "category_uid": 6, "class_uid": 6003, "type_uid": 600301 },
  "ts": "2026-05-24T19:05:13.478Z",
  "session": {
    "id": "sess_f5d2f91d1fb899cd",
    "mcp_protocol_version": "2025-06-18",
    "mcp_capabilities": { "sampling": {}, "tools": {} }
  },
  "host": { "name": "my-workstation", "os": "darwin" },
  "user": { "name": "andrew" },
  "process": { "pid": 1234, "executable": "/usr/local/bin/mcpshark" },
  "mcp": {
    "transport": "stdio",
    "server_name": "my-server",
    "direction": "server_to_client",
    "method": "sampling/createMessage",
    "request_id": 1
  },
  "payload": {
    "params_sha256": "a7c3e9...",
    "params_size_bytes": 323
  },
  "detections": [
    {
      "rule_id": "mcp.sampling.create",
      "severity": "high",
      "confidence": 0.95,
      "detector": "methods",
      "atlas": "AML.T0054",
      "attck": "T1059",
      "detail": "A server->client sampling request was intercepted..."
    }
  ]
}
```

---

## Flags

```
mcpshark run [flags] -- <command> [args...]

  --name, -n       Server label in events (default: command basename)
  --output, -o     Event destination: - for stderr, or a file path (default: -)
  --redaction, -r  Params handling: reference_only | sampled | full (default: reference_only)
  --log-level      debug | info | warn | error (default: info)
  --fail-closed    Halt on proxy error; default is fail-open with logged alert
  --allowlist, -a  Path to server allowlist YAML
```

**Redaction modes:**
- `reference_only` (default): SHA-256 hash + size only. Safe for production SIEMs.
- `sampled`: hash always, raw params for ~1% of events. Good for production debugging.
- `full`: hash + raw params for every event. Development / isolated environments only.

---

## Sigma rules

Twelve production-ready Sigma rules ship in `sigma-rules/`:

| File | Level |
|------|-------|
| `mcp_sampling_request.yml` | high |
| `mcp_tool_poisoning_drift.yml` | high |
| `mcp_prompt_injection_detected.yml` | high |
| `mcp_sampling_exfil_pattern.yml` | **critical** |
| `mcp_tool_call_credential_path.yml` | high |
| `mcp_resources_read_sensitive.yml` | high |
| `mcp_unknown_server_identity.yml` | high |
| `mcp_large_sampling_request.yml` | medium |
| `mcp_elicitation_request.yml` | medium |
| `mcp_high_frequency_tool_calls.yml` | medium |
| `mcp_roots_list_recon.yml` | low |
| `mcp_server_log_notification.yml` | info |

---

## Detection architecture

```
JSON-RPC message
  │
  ├── Forward unchanged ──► child MCP server  (never delayed)
  │
  └── Detection pipeline
        ├── methods:   zero-false-positive S2C method flagging
        ├── drift:     SHA-256 fingerprint of tools/list per session
        └── injection: 9 regex patterns on server-controlled text
                │
          OCSF JSON-L event ──► stderr / file / SIEM
```

Forwarding always happens first. Detection latency never touches the protocol.

---

## Building from source

```bash
git clone https://github.com/andrewhannaford/mcpshark
cd mcpshark
make build   # ./mcpshark
make test    # 27 tests across detect and proxy packages
make lint    # golangci-lint
```

Requires Go 1.22+. No CGO. Compiles for macOS, Linux, and Windows.

---

## Threat model

**Catches:** `sampling/createMessage` (server-initiated LLM calls), `elicitation/create` (credential phishing), `roots/list` (workspace recon), tool description drift (rug-pull), prompt injection keywords in server-controlled text.

**Doesn't catch (yet):** Semantic injection (requires LLM), verified secrets (trufflehog integration, v1.1), Streamable HTTP transport (v2), obfuscated injection.

---

## Roadmap

**v1.0 (current)**
- stdio transparent proxy with forward-first pump
- 9-pattern injection scanner, tool drift detector, server allowlist (SHA-256 pinning)
- 12 Sigma rules with MITRE ATT&CK + ATLAS IDs
- Full Splunk app: props.conf, transforms.conf, two dashboards, lookup tables
- OCSF Application Activity (class 6003) JSON-L output

**v1.1**
- Trufflehog verified secrets detection in tool call params and results
- Unicode normalization to catch homoglyph injection bypass (see `docs/bypass-paths.md`)
- Prometheus `/metrics` endpoint (`--metrics-port` flag)

**v1.2**
- Cross-session drift persistence (SQLite state store)
- Homebrew tap for one-line install

**v2.0**
- Streamable HTTP / SSE transport support

---

## Author

[Andrew Hannaford](https://andrewhannaford.com) — Senior Detection Engineer at Brex.

---

Apache 2.0. See [LICENSE](LICENSE).

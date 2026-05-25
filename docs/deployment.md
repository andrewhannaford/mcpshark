# Deployment Guide

## Quick Start

```sh
# Install
go install github.com/andrewhannaford/mcpshark@latest

# Run any MCP server through mcpshark
mcpshark run -- npx -y @modelcontextprotocol/server-filesystem /tmp

# With detection output to file
mcpshark run --output /var/log/mcpshark/events.jsonl -- npx -y @modelcontextprotocol/server-filesystem /tmp

# With allowlist enforcement
mcpshark run --allowlist ~/.mcpshark/allowlist.yaml --output - -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

## Claude Desktop Integration

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

**Before:**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

**After (wrap with mcpshark):**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcpshark",
      "args": [
        "run",
        "--server-name", "filesystem",
        "--output", "/tmp/mcpshark-events.jsonl",
        "--allowlist", "/Users/you/.mcpshark/allowlist.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"
      ]
    }
  }
}
```

## Cursor Integration

Edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcpshark",
      "args": [
        "run",
        "--server-name", "filesystem",
        "--output", "/tmp/mcpshark-events.jsonl",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"
      ]
    }
  }
}
```

## Flags Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--server-name` | derived from command | Override server display name |
| `--output` | `-` (stderr) | Event destination: file path or `-` for stderr |
| `--redact` | `reference_only` | Payload redaction: `reference_only`, `sampled`, `full` |
| `--allowlist` | *(disabled)* | Path to allowlist YAML |

## SIEM Integration

### Splunk

1. Install the mcpshark Splunk app (`splunk-app/` directory).
2. Add a file monitor in `inputs.conf`:
   ```ini
   [monitor:///var/log/mcpshark/*.jsonl]
   sourcetype = mcpshark
   index = security
   ```
3. Events appear in the **mcpshark Overview** and **Detections** dashboards immediately.

### Elastic / OpenSearch

Use Filebeat with the NDJSON input:

```yaml
filebeat.inputs:
  - type: filestream
    id: mcpshark
    paths:
      - /var/log/mcpshark/*.jsonl
    parsers:
      - ndjson:
          target: ""
          add_error_key: true
```

### Syslog / any SIEM

Pipe output to `logger`:
```sh
mcpshark run --output - -- <server> 2>&1 | grep -v '^mcpshark:' | logger -t mcpshark
```

## Production Considerations

### Output File Rotation

mcpshark writes append-only to the output file. Use `logrotate` or similar:

```
/var/log/mcpshark/*.jsonl {
    daily
    rotate 30
    compress
    missingok
    notifempty
    postrotate
        # mcpshark reopens on SIGHUP (not yet implemented — use copytruncate for now)
    endscript
    copytruncate
}
```

### Allowlist Management

Generate SHA-256 for a new server:

```sh
# macOS / Linux
shasum -a 256 $(which npx)

# Windows (PowerShell)
Get-FileHash (Get-Command npx).Source -Algorithm SHA256
```

Add to `~/.mcpshark/allowlist.yaml`:
```yaml
servers:
  - name: my-new-server
    sha256: "abc123..."
    description: "Approved 2026-05-24 by @andrew — official package from vendor"
```

### Redaction Policy

| Environment | Recommended `--redact` |
|-------------|----------------------|
| Production SOC | `reference_only` (default) — no raw params stored |
| IR / investigation | `sampled` — 1% sample for forensic context |
| Local dev / testing | `full` — full params visibility |

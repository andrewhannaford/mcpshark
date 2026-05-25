# Demo Guide

Two scenarios that showcase mcpshark's detection capabilities. Both use Go servers from the `corpus/` directory — no external dependencies.

## Scenario 1: Sampling + Prompt Injection (evil-server)

**What it shows:** A malicious MCP server sends `sampling/createMessage` with an "Ignore previous instructions" payload targeting `~/.ssh/id_rsa`.

**Expected detections:** 4 rules fire simultaneously:
- `mcp.sampling.create` (high)
- `mcp.injection.ignore_instructions` (high)
- `mcp.injection.file_exfil_target` (high)
- `mcp.injection.verbatim_response` (high)

### Steps

```sh
# Build the demo server
go build -o /tmp/evil-server ./corpus/traces/evil-server

# Prepare a fixture client message (initialize + tools/list)
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"1.0"}}}\n{"jsonrpc":"2.0","method":"notifications/initialized"}\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' > /tmp/demo-input.jsonl

# Run mcpshark wrapping evil-server
mcpshark run \
  --server-name evil-demo \
  --output - \
  -- /tmp/evil-server < /tmp/demo-input.jsonl
```

You should see 4 events on stderr; the last one will have `"detections":[...]` with all 4 rules.

### Expected output (abridged)

```json
{"ts":"...","mcp":{"server_name":"evil-demo","direction":"s2c","method":"sampling/createMessage"},"detections":[
  {"rule_id":"mcp.sampling.create","severity":"high","confidence":0.95},
  {"rule_id":"mcp.injection.ignore_instructions","severity":"high","confidence":0.90},
  {"rule_id":"mcp.injection.file_exfil_target","severity":"high","confidence":0.85},
  {"rule_id":"mcp.injection.verbatim_response","severity":"high","confidence":0.80}
]}
```

---

## Scenario 2: Tool Rug-Pull / Drift (drifting-server)

**What it shows:** A server changes its tool description between `tools/list` calls — a rug-pull attack where initial trust is established with benign descriptions, then poisoned.

**Expected detections:** Second call fires 2 rules:
- `mcp.tools.drift` (high)
- `mcp.injection.file_exfil_target` (high) — injected in the new description

### Steps

```sh
# Build the demo server
go build -o /tmp/drifting-server ./corpus/traces/drifting-server

# Input: initialize + two tools/list calls
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"1.0"}}}\n{"jsonrpc":"2.0","method":"notifications/initialized"}\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}\n' > /tmp/drift-input.jsonl

# Run mcpshark wrapping drifting-server
mcpshark run \
  --server-name drift-demo \
  --output - \
  -- /tmp/drifting-server < /tmp/drift-input.jsonl
```

The first `tools/list` response is clean (no detections). The second fires `mcp.tools.drift` + injection.

---

## GIF Recording (LinkedIn post)

Use [vhs](https://github.com/charmbracelet/vhs) for a clean, reproducible terminal recording:

```vhs
Output demo.gif
Set Theme "Catppuccin Mocha"
Set FontSize 14
Set Width 1200
Set Height 600

Type "mcpshark run --server-name evil-demo --output - -- /tmp/evil-server < /tmp/demo-input.jsonl"
Enter
Sleep 3s
```

Terminal width 120, font 14, dark theme. The GIF should loop cleanly: detection fires, pause 2 seconds, loop.

## LinkedIn Caption

> Your AI assistant is having conversations you can't see.
> mcpshark shows you every one of them.
>
> Built mcpshark — an open-source MCP security proxy. Wraps any MCP server, captures every JSON-RPC message, and runs a detection pipeline for prompt injection, tool rug-pulls, and credential exfiltration — before your LLM client ever sees the response.
>
> Detection output is OCSF-aligned JSON-L. Drop the included Splunk app on top and you have dashboards in 5 minutes.

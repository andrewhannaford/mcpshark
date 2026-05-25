# mcpshark Threat Model

## What mcpshark Protects

mcpshark sits between an MCP client (Claude Desktop, Cursor, Cline) and an MCP server, capturing and analyzing all JSON-RPC traffic. It aims to detect attacks where the MCP server is adversarial or compromised.

```
[LLM Client] <--stdio--> [mcpshark proxy] <--stdio--> [MCP Server]
```

The key threat model assumption: **the MCP client and host are trusted; the MCP server is not.**

---

## Threat Categories

### 1. Prompt Injection via Server-Controlled Text

**Attack**: The server embeds adversarial instructions in fields the LLM will read:
- Tool descriptions (returned by `tools/list`)
- Sampling request content (`sampling/createMessage`)
- Elicitation prompts (`elicitation/create`)
- Log notifications (`notifications/message`)

**Goal**: Cause the LLM to exfiltrate data, call unintended tools, or ignore user instructions.

**Detection**: `mcp.injection.*` rules — 9 regex patterns covering jailbreak phrases, credential file paths, exfiltration URLs, role hijacking, and verbatim-output instructions.

**Limitation**: Pattern-based; novel/obfuscated injection may evade. Unicode homoglyph substitution and base64-encoded payloads are not currently detected.

---

### 2. Tool Rug-Pull (Drift)

**Attack**: A server advertises benign tool descriptions during initial trust establishment (`tools/list`), then returns different (malicious) descriptions in a later `tools/list` response. The LLM caches the initial description; the actual execution behavior has changed.

**Goal**: Bypass static allow-listing or prompt-based approval that only runs at session start.

**Detection**: `mcp.tools.drift` — SHA-256 fingerprint of `result.tools` array; any change fires a high-severity alert.

**Limitation**: First call is trusted. If the very first `tools/list` is already malicious, drift detection won't fire (but injection detection may). Structural heuristic (checking `result.tools`) may miss non-standard server implementations.

---

### 3. Sampling Request Abuse (`sampling/createMessage`)

**Attack**: The server sends a `sampling/createMessage` request, directing the client LLM to execute an arbitrary completion — effectively a server-side remote execution primitive.

**Goal**: Chain from tool execution into LLM execution; pivot from one context to another.

**Detection**: `mcp.sampling.create` fires on every `sampling/createMessage` observed. Compound rule `mcp.sampling.exfil_pattern` fires when sampling + credential-path injection co-occur.

**Limitation**: Legitimate servers also use sampling. Detection is informational unless combined with injection signals.

---

### 4. Supply Chain / Unknown Server Identity

**Attack**: A malicious server impersonates a legitimate one by name (e.g., `filesystem`), or a legitimate server binary is replaced with a trojanized version.

**Goal**: Gain execution in a trusted MCP context without triggering name-based allow-listing.

**Detection**: `mcp.allowlist.unknown_server` — compares server binary SHA-256 against an allowlist (`--allowlist` flag). Hash mismatch or unlisted server fires high-severity alert.

**Limitation**: Hash is of the *interpreter* (node, python) not the MCP package script. Two different servers using the same interpreter are indistinguishable by hash alone. Full binary pinning requires a compiled Go/Rust MCP server.

---

### 5. Sensitive Resource/Credential Access

**Attack**: The server reads sensitive files (SSH keys, `.env`, cloud credentials) via `resources/read`, or passes credential paths as tool arguments.

**Goal**: Exfiltrate secrets to server-controlled storage.

**Detection**: `mcp.tool_call.credential_path` and `mcp.resources.read_sensitive` — pattern-match on common credential paths in tool arguments and resource URIs.

**Limitation**: Detects access, not exfiltration. The server could read credentials in small chunks or encode them in non-obvious ways.

---

## Out of Scope

| Threat | Why Out of Scope |
|--------|-----------------|
| Attacks originating from the LLM client | Client is trusted; mcpshark does not inspect LLM outputs |
| Network-based attacks | mcpshark only handles stdio transport |
| Server-side SSRF / code execution | Server is already running; mcpshark doesn't sandbox it |
| MCP server DoS | mcpshark forwards all traffic and won't block requests |
| Post-compromise persistence (server side) | Out of scope for a proxy monitor |

---

## Trust Boundaries

```
TRUSTED                          UNTRUSTED
───────────────────────────────────────────
Host OS                          MCP server process
OS user running mcpshark         Server binary (unless allowlisted)
LLM client process               Server-provided tool descriptions
mcpshark itself                  Server-controlled sampling content
```

---

## Bypass Paths

See [bypass-paths.md](bypass-paths.md) for documented weaknesses and corresponding planned mitigations.

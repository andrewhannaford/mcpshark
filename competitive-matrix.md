# Competitive Analysis — mcpshark

*Researched 2026-05-24. Verify stars/status before publishing.*

## Summary

The MCP security tooling space has two distinct clusters: **static scanners** (check
configs + tool descriptions for known patterns before runtime) and **gateways/policy
proxies** (enforce allow/block rules, primarily HTTP-focused). Neither cluster covers
what mcpshark does: **runtime traffic capture with detection-engineer-grade output**.

There is no publicly available tool that:
- Transparently proxies stdio MCP traffic
- Captures server→client methods (sampling, elicitation, roots)
- Emits OCSF-aligned JSON-L
- Ships with a curated Sigma ruleset + Splunk app

That gap is mcpshark's position.

---

## Comparison table

| Tool | Stars | Lang | Stdio proxy | SIEM output | Sigma rules | Splunk app | sampling/elicitation capture |
|------|-------|------|-------------|-------------|-------------|------------|-------------------------------|
| **mcpshark** (this project) | — | Go | ✅ | ✅ OCSF JSON-L | ✅ 12+ rules | ✅ | ✅ |
| invariantlabs/mcp-scan (Snyk) | 2.5k | Python | ❌ static only | ❌ | ❌ | ❌ | ❌ |
| modelcontextprotocol/inspector | 9.8k | TypeScript | partial (dev tool) | ❌ | ❌ | ❌ | ❌ |
| apache/casbin-gateway | 559 | Go | ❌ HTTP only | ❌ | ❌ | ❌ | ❌ |
| TheLunarCompany/lunar | 446 | TypeScript | ❌ HTTP only | ❌ | ❌ | ❌ | ❌ |
| gebruder/wirken | 150 | Rust | partial | audit log only | ❌ | ❌ | ❌ |
| enkryptai/secure-mcp-gateway | 54 | Python | ❌ gateway | ❌ | ❌ | ❌ | ❌ |
| JanuScope (giancarloerra) | 16 | TypeScript | local proxy | OpenTelemetry | ❌ | ❌ | ❌ |

---

## Per-tool notes

### `invariantlabs-ai/mcp-scan` (2.5k ⭐, Python, Apache-2.0)
Now part of Snyk. Auto-discovers MCP configs, executes servers, scans tool descriptions
for prompt injections and malware. **Key difference:** static analysis, not runtime
interception. Fires before the session starts, not during. Misses everything that happens
at runtime — sampling abuse, drift, in-flight secrets, elicitation. Our tools are
complementary; we should say that explicitly in the README.

**README CTA:** *"Run mcp-scan to vet your MCP servers before installation.
Run mcpshark during every session to catch what mcp-scan can't see at runtime."*

### `modelcontextprotocol/inspector` (9.8k ⭐, TypeScript, MIT)
Anthropic's official debug tool. Protocol bridge (stdio → web UI) for interactive
testing. Not a security tool; no logging, no detection, no SIEM. The "isn't this just
Inspector?" challenge is easy to answer: Inspector is a screwdriver; mcpshark is a
Wireshark tap. Different job.

### `casbin-gateway`, `lunar`, `enkryptai/secure-mcp-gateway`
Gateway/proxy pattern — enforce allow/deny rules, primarily over HTTP. None capture
stdio, none emit structured detection events, none have Sigma rules. These are policy
enforcers; mcpshark is an observer. Complementary, not competitive.

### `JanuScope` (16 ⭐, TypeScript)
Closest competitor on the proxy side: local-first policy proxy with audit logging and
OpenTelemetry. But TypeScript, no Sigma/SIEM, no sampling capture, 16 stars. Not a threat
today; watch it if it grows.

---

## Positioning statement for README and LinkedIn

> Most MCP security tools are static scanners or policy gates. They check what tools
> exist; they don't watch what happens when those tools run.
>
> mcpshark watches. Every tool call, every resource read, every time a server tells
> your LLM to run a prompt — all of it captured, all of it inspectable, all of it
> flowing into your SIEM in a format your Sigma rules can query.

---

## Risks to monitor

1. **Anthropic ships official runtime logging** in Claude Desktop or the MCP SDK — likely
   eventually. Mitigation: position detection content as the durable asset; ship
   *"works with mcpshark or official Anthropic logs"* framing early.
2. **mcp-scan / Snyk adds runtime mode** — they have the distribution. Watch their
   changelog. Mitigation: go deeper on detection engineering content.
3. **JanuScope or a well-funded fork adds SIEM output** — unlikely at 16 stars, but
   watch. Mitigation: ship the Splunk app and Sigma rules before they do.

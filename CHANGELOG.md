# Changelog

All notable changes to mcpshark will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

**Core proxy**
- `internal/proxy/pump.go` — Forward-first NDJSON pump with UTF-8 BOM stripping; safe for Windows MCP clients
- `internal/proxy/event.go` — Full OCSF Application Activity (class 6003) event builder with server binary SHA-256, redaction modes (`reference_only`, `sampled`, `full`), and session state tracking
- `internal/output/jsonl.go` — Fixed: `-` destination writes to stderr (not stdout) to avoid corrupting MCP protocol passthrough

**Detection pipeline**
- `internal/detect/drift.go` — Tools/list fingerprint drift detector; session-scoped SHA-256 comparison with structural heuristic to identify tools/list responses without request correlation
- `internal/detect/injection.go` — 9-pattern regex injection scanner covering: jailbreak phrases, file exfil targets, credential keywords, verbatim-output instructions, hidden instructions, data exfil URLs, role hijacking
- `internal/detect/allowlist.go` — YAML-based server allowlist enforcement; hash-first matching (confidence 0.95) with name-only fallback (0.70); fires once per session

**Schema and protocol**
- `pkg/schema/event.go` — Complete OCSF Application Activity (class 6003) event type with detections array
- `internal/protocol/jsonrpc.go` — JSON-RPC 2.0 types + MCP method constants including sampling/createMessage and elicitation/create

**Test corpus**
- `corpus/traces/evil-server/` — Demo server: fires sampling/createMessage with "Ignore previous instructions" payload
- `corpus/traces/drifting-server/` — Demo server: rug-pull attack; benign description first, poisoned second
- `corpus/traces/mcp-client/` — Minimal MCP client for interactive testing
- `corpus/README.md` — Scenario documentation with exact reproduction steps

**Detection content**
- 12 Sigma rules in `sigma-rules/` covering all threat categories (sampling abuse, injection, drift, supply chain, credential access, recon)
- MITRE ATT&CK + ATLAS IDs on all rules

**SIEM integration**
- `splunk-app/default/props.conf` — JSON extraction, field aliases (OCSF -> mcp_* names), CIM mappings
- `splunk-app/default/transforms.conf` — Severity and rules lookups, detection field extraction
- `splunk-app/default/app.conf` — App metadata
- `splunk-app/default/data/ui/views/mcp_overview.xml` — Overview dashboard: summary tiles, traffic timeline, top methods, server summary, recent events
- `splunk-app/default/data/ui/views/mcp_detections.xml` — Detections dashboard: alert counts, severity timeline, ATT&CK/ATLAS heatmap, rule summary, session drill-down
- `splunk-app/lookups/mcpshark_severity.csv` — Severity level mapping
- `splunk-app/lookups/mcpshark_rules.csv` — Rule ID to name/description/MITRE mapping
- `splunk-app/metadata/default.meta` — Splunk app permissions

**Documentation**
- `docs/schema.md` — Full OCSF event schema reference with field table and example event
- `docs/threat-model.md` — Threat categories, trust boundaries, and out-of-scope items
- `docs/bypass-paths.md` — Honest documentation of 6 known detection bypass paths with planned mitigations
- `docs/deployment.md` — Claude Desktop, Cursor integration; Splunk, Elastic, syslog ingestion; allowlist management; log rotation
- `docs/attck-mapping.md` — Rule-level MITRE ATT&CK and ATLAS mapping tables
- `README.md` — Full production README with detection table, architecture diagram, OCSF schema example, flags reference

**Examples**
- `examples/allowlist.yaml` — Template allowlist with filesystem, github, brave-search entries and SHA-256 instructions
- `examples/cursor-mcp-config.json` — Cursor MCP config with mcpshark wrapping

**Build**
- `.goreleaser.yml` — Multi-platform release config with cosign signing + SBOM generation
- `go.mod` / `go.sum` — Added `gopkg.in/yaml.v3` for allowlist parsing

### Fixed
- Stdout collision: events were written to stdout, corrupting MCP protocol passthrough on pipes
- UTF-8 BOM from PowerShell caused first event to be silently dropped (`json.Unmarshal` failure on `0xef 0xbb 0xbf` prefix)
- Unicode `->` arrows in pipeline detail strings appeared as mojibake in non-UTF-8 terminals

### Initial skeleton (Week 0)
- Cobra CLI scaffold with `run` subcommand
- OCSF event schema stub
- `internal/detect/pipeline.go` — detector interface and fan-out
- Cross-platform process group management
- Two Sigma rules: `mcp_sampling_request`, `mcp_tool_poisoning_drift`
- Example `claude_desktop_config.json`

# Changelog

All notable changes to mcpshark will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Initial project skeleton with cobra CLI, OCSF event schema, stdio proxy stub
- `run` subcommand with full flag surface
- `pkg/schema/event.go` — complete OCSF Application Activity (class 6003) event type
- `internal/protocol/jsonrpc.go` — JSON-RPC 2.0 types + MCP method constants including
  sampling/createMessage and elicitation/create (high-risk server→client methods)
- `internal/detect/pipeline.go` — detector interface and fan-out stub
- `internal/output/jsonl.go` — buffered JSON-L emitter with mutex
- Cross-platform process group management (Setpgid on Unix, stub for Windows Job Objects)
- Two Sigma rules: mcp_sampling_request, mcp_tool_poisoning_drift
- goreleaser config with cosign signing + SBOM generation
- Example claude_desktop_config.json for common MCP servers

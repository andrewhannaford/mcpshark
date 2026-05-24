# mcpshark — Detailed Build Plan (v1.0, hardened)

> **What it is:** A local MCP (Model Context Protocol) traffic monitor that captures, decodes, and detects security-relevant events in MCP sessions between AI clients (Claude Desktop, Cursor, Cline, etc.) and MCP servers. Emits OCSF-aligned JSON-L for SIEM ingestion, ships with a curated Sigma ruleset and a Splunk app.
>
> **What it isn't:** A control plane. A sandbox. An enterprise gateway. This is a *visibility* tool — be honest about that in the README.

This plan has been through three rounds of adversarial review (SOC engineer, OSS/growth advocate, MCP protocol expert) and folds in their critiques. See `REVIEWS.md` for the source critiques if needed.

---

## 0. North Star

A senior detection engineer scrolling LinkedIn at 9am sees a GIF: Claude Desktop runs an innocent-looking prompt, the right-hand pane lights up red as `mcpshark` flags a `sampling/createMessage` exfil attempt. They click through, `brew install mcpshark`, point Claude Desktop at it, and 90 seconds later they're tailing JSON-L. The repo has a Sigma rule that names the attack and a Splunk dashboard that visualises it.

That moment is the product. Every scope decision below serves it.

---

## 1. Strategic Decisions (locked before code)

### 1.1 Name and brand
- **Name:** `mcpshark` (Wireshark analogy — instantly legible to the security audience; "watch" is too generic and collides with `kubectl --watch` etc.)
- **Tagline:** *"Wireshark for the AI tool layer."*
- **Aesthetic:** Terminal-first. Dark theme. No corporate logo. Single ASCII banner in the README.
- **GitHub org:** `andrewhannaford` personal (or a new `mcpshark` org if we want room to grow). Decide before publishing.

### 1.2 Positioning vs. competition
- **Live competitive scan is REQUIRED before writing code.** Confirmed/suspected players to check on GitHub and ship a comparison table for:
  - `invariantlabs-ai/mcp-scan` (static + runtime MCP scanner)
  - `modelcontextprotocol/inspector` (official Anthropic debug proxy)
  - Any `mcp-guardian` / `mcp-gateway` / `SecureMCP` projects
  - Lasso Security / Prompt Armor / Pillar / Protect AI MCP offerings
  - Cribl / Splunk MCP observability content
- **Differentiator:** *"The only MCP visibility tool that ships with detection content out of the box — Sigma rules, a Splunk app, and a documented attack-scenario corpus written by a detection engineer who does this for a living."* The proxy is the lead magnet; the detection content is the moat.
- **Pivot trigger:** If a project with >500 stars already covers stdio proxy + JSON-L + Sigma rules, pivot to "MCP detection content + reference proxy fixtures" — i.e. own the rule library, treat the proxy as a reference implementation.

### 1.3 Scope cuts (vs. the original plan)
| Original plan | Final v1 | Reason |
|---|---|---|
| stdio proxy | ✅ Keep | Table stakes |
| HTTP/SSE proxy | ❌ **Cut from v1**, mark "v2" | 2+ weeks alone; spec is in flux (Streamable HTTP); cutting it lets us ship detection content properly |
| JSON-RPC parsing | ✅ Keep + version-aware (see §3.3) | Must handle batched (pre-2025-06-18) and non-batched correctly |
| Pattern detection | ✅ Replaced with **trufflehog-backed secrets + curated detection layer** | Don't reinvent; integrate a serious detector |
| Allowlist of servers | ✅ Keep + **cryptographic identity** (binary hash for stdio) | Name strings are forgeable |
| Splunk dashboard | ✅ Keep — **this is a headline deliverable** | Differentiator |
| Sigma rules | ✅ Keep — **minimum 12 tested rules, not toys** | Differentiator |
| Demo recording | ✅ Keep — **built in Week 1**, not Week 6 | Demo drives the whole product shape |

### 1.4 Threat model — what mcpshark v1 catches and what it doesn't

**Caught (high-confidence):**
- `tools/list` drift over time (rug-pull / tool poisoning)
- `sampling/createMessage` requests (server-initiated LLM calls — the #1 missed attack)
- `elicitation/create` prompts (server asking the user for data)
- `roots/list` requests (workspace recon)
- Verified secrets in tool inputs/outputs (via trufflehog)
- Known-bad domains / IPs in tool params and results
- Use of MCP servers not on the cryptographic allowlist
- Indirect prompt-injection keyword patterns in `resources/read` and tool results
- Protocol violations (batching on a current-version session, embedded newlines in stdio frames, duplicate IDs)

**Not caught (must be explicit in the README):**
- Out-of-band tool execution by the AI client (not via MCP)
- Custom transports outside stdio (Unix sockets, named pipes, in-process)
- HTTP MCP servers (v2)
- Cross-session causal chains (no LLM turn correlation in v1; flag as a v2 enhancement)
- Anything happening inside a server binary that doesn't surface on the wire

The README explicitly states this is a **visibility** tool, not a control plane — sets expectations and pre-empts the "but a malicious client just bypasses it" critique.

---

## 2. Architecture

```
                                        [stderr → tee → mcpshark.stderr.log]
                                                  ▲
[AI Client] ── stdin ──▶ [mcpshark proxy] ── stdin ──▶ [real MCP server]
            ◀── stdout ──                   ◀── stdout ──
                  │
                  ├──▶ [JSON-RPC parser + correlator]
                  │              │
                  │              ▼
                  │      [detection pipeline]
                  │       ├── trufflehog (verified secrets)
                  │       ├── prompt-injection keyword scanner
                  │       ├── allowlist enforcement
                  │       ├── tools/list drift tracker (persistent state)
                  │       └── method-specific rules (sampling/elicitation/roots)
                  │              │
                  │              ▼
                  └──▶ [OCSF JSON-L emitter]
                          ├── stdout / file / syslog
                          ├── Prometheus /metrics (bind opt-in)
                          └── bounded ring buffer + drop counters
```

### 2.1 Deployment models supported in v1
1. **Wrapper mode (default):** AI client config rewritten to invoke `mcpshark --target <real-command> [args]` instead of the real server. mcpshark wraps the child process.
2. **Tee mode (advanced):** mcpshark reads from a fifo / file and analyses pre-captured traces. Useful for incident response and for the test corpus.

**Explicitly out for v1:** centralised gateway, MDM deployment profiles, eBPF interception. These are documented in the roadmap as v2/v3 explorations; the README is honest that wrapper-mode is a developer-laptop / pilot-scale tool, not an enterprise control.

### 2.2 Repo layout
```
mcpshark/
├── cmd/mcpshark/
│   └── main.go                          # cobra root, version, --help
├── internal/
│   ├── proxy/
│   │   ├── stdio.go                     # stdin/stdout pumping, process lifecycle
│   │   ├── stdio_unix.go                # SIGTERM, process groups (Setpgid)
│   │   ├── stdio_windows.go             # Job Objects, taskkill
│   │   └── shutdown.go                  # close-stdin → SIGTERM → SIGKILL ladder
│   ├── protocol/
│   │   ├── jsonrpc.go                   # parser, batch support gated on protocol version
│   │   ├── correlator.go                # (direction, id) keyed map; progress tokens
│   │   ├── lifecycle.go                 # initialize handshake, capabilities, version pinning
│   │   └── methods.go                   # canonical method name constants
│   ├── detect/
│   │   ├── pipeline.go                  # detector interface, fan-out
│   │   ├── trufflehog.go                # secrets via trufflehog library
│   │   ├── injection.go                 # prompt-injection keyword/heuristic scanner
│   │   ├── allowlist.go                 # server identity + binary hash
│   │   ├── drift.go                     # tools/list fingerprint + drift state
│   │   └── methods.go                   # sampling/elicitation/roots flagging
│   ├── output/
│   │   ├── ocsf.go                      # OCSF schema mapping (class 6003)
│   │   ├── jsonl.go                     # JSON-L sink with bounded buffer + flusher
│   │   ├── syslog.go                    # optional
│   │   ├── metrics.go                   # Prometheus /metrics
│   │   └── splunk_cim.go                # CIM field aliases as a side-export
│   ├── state/
│   │   └── store.go                     # local sqlite for drift fingerprints, session state
│   └── corpus/
│       └── fixtures.go                  # malicious-traffic test corpus loader
├── pkg/schema/
│   └── event.go                         # exported event struct + schema_version
├── examples/
│   ├── claude-desktop-config.json
│   ├── cursor-mcp-config.json
│   └── continue-config.json
├── splunk-app/
│   ├── default/
│   │   ├── props.conf
│   │   ├── transforms.conf
│   │   ├── data/ui/views/mcp_overview.xml
│   │   ├── data/ui/views/mcp_detections.xml
│   │   └── eventgen.conf
│   └── README.md
├── sigma-rules/
│   ├── mcp_tool_poisoning_drift.yml
│   ├── mcp_sampling_request.yml
│   ├── mcp_elicitation_pii_request.yml
│   ├── mcp_roots_list_reconnaissance.yml
│   ├── mcp_verified_secret_in_tool_io.yml
│   ├── mcp_unknown_server_invoked.yml
│   ├── mcp_prompt_injection_keyword.yml
│   ├── mcp_protocol_violation_batched.yml
│   ├── mcp_resource_read_external_url.yml
│   ├── mcp_high_volume_tool_calls.yml
│   ├── mcp_oauth_token_in_params.yml
│   └── mcp_consecutive_tool_errors.yml
├── corpus/
│   ├── traces/                          # captured fixtures, one .jsonl per scenario
│   └── README.md                        # what each scenario demonstrates
├── docs/
│   ├── threat-model.md
│   ├── schema.md                        # OCSF mapping + CIM aliases
│   ├── deployment.md                    # client-by-client config rewriting
│   ├── bypass-paths.md                  # honest accounting of what we don't catch
│   └── attck-mapping.md                 # MITRE ATT&CK + ATLAS mapping
├── .goreleaser.yml
├── Brewfile                             # for the eventual homebrew tap
├── Dockerfile
├── README.md                            # GIF-above-the-fold, comparison table
├── DEMO.md                              # how to reproduce the demo GIF locally
├── SECURITY.md                          # disclosure policy
├── CHANGELOG.md
└── LICENSE                              # MIT or Apache-2.0
```

---

## 3. Technical decisions (the ones reviewers flagged)

### 3.1 stdio plumbing — non-negotiables
- Use `bufio.Reader.ReadBytes('\n')` (NOT `bufio.Scanner` with defaults — its 64 KB ceiling truncates large `tools/call` results). Configurable max-message cap with `truncated: true` flag in the event.
- Forward `stderr` verbatim to parent's stderr **and** tee to `mcpshark.stderr.log`. Never mix into stdout.
- After every framed write to child or parent, explicit `Flush()` — Go's `os.Stdout` is block-buffered when redirected and will stall the handshake otherwise.
- Inherit full env (or merge with client-supplied `env`) and cwd from the launching client.
- Forward `SIGINT`, `SIGHUP` (Unix), and the Windows console close-event to the child.
- Cross-platform process groups: `syscall.SysProcAttr{Setpgid: true}` on Unix; Job Objects on Windows (so a wrapper crash doesn't orphan the child).
- Shutdown ladder per MCP lifecycle spec: parent closes our stdin → close child's stdin → wait with timeout → SIGTERM → wait → SIGKILL. Windows uses `taskkill /F` + Job Object close.
- Propagate child exit code as our own: `os.Exit(child.ProcessState.ExitCode())`.
- Fail-open by default (don't brick dev tooling); `--fail-closed` flag for high-sec envs.
- Independent goroutines per direction, context-cancel propagation, bounded channels so a slow log sink can't deadlock the protocol.

### 3.2 What gets captured (corrects original plan's omissions)
v1 captures **all** methods bidirectionally, with structured handling for these (this list is the headline correction from the protocol reviewer):

| Method | Direction | Why it matters |
|---|---|---|
| `initialize` / `initialized` | C↔S | Pin protocol version + capabilities per session |
| `tools/list` | S→C response | Drift fingerprinting (rug-pull detection) |
| `tools/call` | C→S + S→C | Inputs and outputs both detected |
| `resources/read` | C→S + S→C | Indirect prompt-injection surface |
| `resources/list` | S→C response | Inventory |
| `prompts/get` | S→C response | Prompt-injection surface |
| **`sampling/createMessage`** | **S→C** | **#1 missed attack vector — server asks client to run an LLM call** |
| **`elicitation/create`** | **S→C** | **Server asks user for structured data** |
| `roots/list` | S→C | Workspace layout disclosure |
| `notifications/*` | both | Includes `progress`, `cancelled`, `message` (logging — leakage risk), `tools/list_changed` (triggers drift recheck) |
| `ping` | both | Liveness — useful only as protocol violations |

Method filtering is **query-time only**, never at capture. The capture layer is always-on; users decide what to surface.

### 3.3 JSON-RPC handling
- Detect protocol version from `initialize` exchange. Accept JSON-RPC batches only when negotiated version < `2025-06-18`. Batch arrival on a current-version session = log as protocol violation (security-relevant signal).
- Correlation key: `(direction, id)` — IDs are direction-scoped per spec. IDs may be strings or integers; store as `json.RawMessage` or `any`, never `int64`.
- Track progress tokens separately via `params._meta.progressToken`, not via `id`.
- Notifications have no id and must never receive a response — proxy must not invent one.
- Validate UTF-8; log encoding violations.

### 3.4 Output schema (OCSF Application Activity, class 6003)

Single JSON-L event per message, mapped to OCSF where possible:

```json
{
  "schema_version": "1.0.0",
  "ocsf": {
    "category_uid": 6,
    "class_uid": 6003,
    "type_uid": 600301,
    "severity_id": 1,
    "activity_id": 1,
    "time": 1748083800000
  },
  "ts": "2026-05-24T10:30:00.123Z",
  "session": {
    "id": "sess_abc123",
    "mcp_protocol_version": "2025-06-18",
    "mcp_capabilities": {"tools": {}, "sampling": {}}
  },
  "host": {"name": "andrew-laptop.local", "os": "darwin"},
  "user": {"name": "andrew"},
  "process": {
    "pid": 14823,
    "executable": "/opt/homebrew/bin/mcpshark",
    "parent_pid": 14801,
    "parent_executable": "/Applications/Claude.app/.../Claude"
  },
  "mcp": {
    "transport": "stdio",
    "server_name": "filesystem",
    "server_identity_sha256": "9f2e...",
    "direction": "client_to_server",
    "method": "tools/call",
    "request_id": "42",
    "tool_name": "read_file",
    "outcome": "success",
    "error_code": null
  },
  "payload": {
    "params_sha256": "sha256:abcd...",
    "params_size_bytes": 1234,
    "params_truncated": false,
    "params_redacted": "<configurable: full | sampled | reference-only>",
    "params_reference_id": "blob_xyz789"
  },
  "detections": [
    {
      "rule_id": "mcp.tools_call.verified_secret",
      "name": "Verified AWS access key in tool input",
      "severity": "high",
      "confidence": 0.99,
      "verified": true,
      "detector": "trufflehog",
      "atlas": "AML.T0024",
      "attck": "T1552"
    }
  ]
}
```

Schema decisions baked in:
- **`schema_version`** is mandatory (reviewers all flagged this — future-proofing).
- **`params_redacted`** has three modes: `full` (include raw, dev/local only), `sampled` (1% sample full + always-hash), `reference-only` (default for production — emit a reference id pointing to a separate, locally-encrypted blob store). Solves the legal/PII-in-SIEM problem.
- **`outcome` + `error_code`** present always — enables the "10 consecutive tool errors" class of detections.
- **`server_identity_sha256`** is the SHA-256 of the resolved server binary (stdio) or TLS leaf cert SPKI (HTTP — v2). Names alone are forgeable.
- **`params_sha256`** is over a canonicalized JSON form (RFC 8785 JCS) — two semantically identical calls produce the same hash.
- **OCSF Application Activity (6003)** as the primary mapping; ship a Splunk CIM TA in parallel for shops that haven't moved to OCSF.

### 3.5 Detection content
- **Secrets:** embed `trufflehog/v3` as a Go library (MIT-licensed). All emitted secret detections include `verified: true|false`. Unverified findings are demoted in severity by default.
- **Prompt injection:** a curated keyword + heuristic pack (e.g. "ignore previous instructions", "you are now", common DAN patterns), with confidence scoring. Be explicit that this is a fast, low-precision first pass — not a replacement for inference-based detection. v2 can add a small classifier.
- **Tool poisoning / drift:** persistent state in local SQLite. Per `(server_identity, tool_name)` we store the first-seen `inputSchema` and `description` hashes. On `tools/list` response, diff and flag changes. Detection rule fires on drift, severity proportional to fields changed.
- **Allowlist:** YAML config with `{name, transport, command, args, env, server_identity_sha256}` blocks. Unknown server = critical-severity event. SHA pinning is opt-in (some users will run servers that auto-update); without pinning we still alert on name mismatch.
- **MITRE mappings:** every Sigma rule has both ATT&CK and ATLAS tags. `docs/attck-mapping.md` ships as a printable table.

### 3.6 Performance budget (publish these numbers)
- p99 added latency per MCP message: **< 5 ms** for messages ≤ 64 KB.
- Memory: bounded at 256 MB per session (configurable).
- Throughput ceiling published after benchmarking on a captured Cursor agent loop (~200 msg/min).
- `/metrics` Prometheus endpoint with drop counters, queue depths, parse errors, detector latencies.

---

## 4. Distribution

| Channel | Priority | Notes |
|---|---|---|
| **GitHub Releases (prebuilt binaries)** | P0 — must ship day one | `goreleaser` config; darwin/arm64, darwin/amd64, linux/amd64, windows/amd64, signed with cosign |
| **Homebrew tap** | P0 | `brew install andrewhannaford/tap/mcpshark`. Required for the LinkedIn audience |
| **Docker image (ghcr.io)** | P1 | For the tee-mode use case in CI / IR |
| **`go install`** | P2 — footnote only | Real users don't have Go installed |
| **apt/rpm** | Skip v1 | Audience isn't there yet |

CI/CD: GitHub Actions → goreleaser → release artifacts, brew formula PR, docker push. SBOM generation via syft, signing via cosign. All checked in from day one.

---

## 5. Build timeline (revised, honest)

Original estimate was 6 weeks. Realistic is **8 weeks** of nights/weekends, with the demo built first.

| Week | Focus | Deliverable at end of week |
|---|---|---|
| **0 (this week)** | Competitive scan, brand lock, repo bootstrap, demo storyboard | `REVIEWS.md`, `competitive-matrix.md`, repo skeleton, scripted demo scenario |
| **1** | Demo-first build: minimal stdio passthrough + fake detection + GIF | Working 20-second demo GIF; everything else stubbed |
| **2** | Real stdio proxy + shutdown ladder + cross-platform process groups | `mcpshark --target` proxies a real MCP server end-to-end on macOS + Linux + Windows |
| **3** | JSON-RPC parser, correlator, lifecycle handling, **sampling/elicitation capture** | All method types parsed and emitted in OCSF JSON-L |
| **4** | Detection pipeline: trufflehog integration, prompt-injection scanner, drift tracker, allowlist | First 4 Sigma rules firing against the corpus |
| **5** | Output: OCSF schema finalised, Splunk CIM TA, Prometheus metrics, bounded buffers | Splunk app loads cleanly, dashboards populate from sample data |
| **6** | Sigma rules complete (12+), test corpus, threat-model docs, ATT&CK/ATLAS mapping | All rules tested against corpus fixtures; docs complete |
| **7** | Polish: README + GIF refresh, goreleaser, brew tap, Docker image, SECURITY.md, eventgen samples | Tagged v1.0.0 release; brew formula merged |
| **8** | LinkedIn post + cross-post (Detection Engineering subreddit, Sigma rule repo PRs, Splunkbase submission) | Post goes live |

### Cut-line if Week 5 slips
- First cut: Docker image (defer to v1.1)
- Second cut: Prometheus metrics (defer to v1.1)
- Never cut: sampling/elicitation capture, Sigma rules, Splunk app, brew tap, README polish, demo GIF

---

## 6. The LinkedIn post (drafted)

**Hook (3 lines, scroll-stop):**
> Claude Desktop just opened 47 files on my laptop without telling me which ones.
>
> Your SOC has zero visibility into what your engineers' AI assistants are doing — and the most dangerous MCP traffic isn't even a tool call.
>
> So I built `mcpshark` to fix that. Detection-engineer-built, ships with Sigma rules + a Splunk app.

**Body:**
- One GIF: split terminal, real detection firing on `sampling/createMessage` exfil.
- One architecture diagram (the ASCII block above, rendered nicely).
- Three sentences on the threat model: tool poisoning, sampling abuse, indirect prompt injection in resources.
- Repo link, brew install one-liner.
- CTA: *"⭐ if you ship MCP servers in prod. Issues, Sigma rule PRs, and Splunk dashboard tweaks welcome."*

**Length:** ~180 words. **Do not** lead with "I built this." Lead with the threat.

---

## 7. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Anthropic ships first-party MCP logging mid-build | Medium | Detection content is the moat; reposition as "works with mcpshark or official logs" |
| MCP spec changes transport semantics again | Medium | Parser tested against captured fixtures, not live transports; pin negotiated version per session |
| A funded competitor drops a polished gateway | Medium | Lean on detection content + Splunk app; commercial gateways won't ship those |
| Performance regressions surface late | Medium | Continuous benchmarks in CI starting Week 3 |
| Scope creep pulls in HTTP/SSE | High | **Hard rule: no HTTP transport in v1. Period.** |
| GitHub Action / brew tap config gotchas | High | goreleaser + brew tap stood up in Week 0, used continuously |
| LinkedIn post lands flat | Medium | Demo GIF tested against 3+ peers before posting; iterate hook copy |
| Legal / PII concerns from `params` capture | Medium | `reference-only` redaction mode is the default; full capture is opt-in dev mode |

---

## 8. What success looks like

**90-day post-launch metrics that mean this worked:**
- 500+ GitHub stars
- 10+ external PRs (Sigma rules, Splunk fixes, client configs)
- 5+ companies running it (visible in issues / discussions)
- 1+ inbound conference talk / podcast invite
- LinkedIn post: 1500+ reactions, 50+ substantive comments from peer detection engineers
- A second LinkedIn post within 60 days about a real attack the tool caught in the wild — this is the multiplier

**What it isn't:** a startup. A SaaS pivot. A polished product. The endgame is profile + a strong artifact that proves the AI-security-detection-engineering thesis Andrew is already building at Brex.

---

## 9. Open questions (decide before Week 0 ends)

1. Personal GitHub or new `mcpshark` org? (Recommendation: personal first; spin out an org only if traction warrants it.)
2. MIT or Apache-2.0? (Recommendation: Apache-2.0 — patent grant matters for security tooling.)
3. Telemetry / phone-home? (Recommendation: **none**. Zero outbound by default. Reinforces the trust narrative.)
4. Brew tap repo name: `homebrew-tap` or `homebrew-mcpshark`? (Recommendation: `homebrew-tap` — reusable for future projects.)
5. Splunk app vs. Splunk add-on (TA) — both? (Recommendation: ship a TA for parsing + a small app for dashboards. Submit TA to Splunkbase, leave app on GitHub.)

---

*Plan v1.0 — finalised 2026-05-24 after three rounds of adversarial review.*

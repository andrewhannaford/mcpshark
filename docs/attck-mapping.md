# MITRE ATT&CK and ATLAS Mapping

Full mapping of mcpshark detection rules to MITRE ATT&CK and ATLAS techniques.

## MITRE ATLAS Coverage

[MITRE ATLAS](https://atlas.mitre.org/) documents adversarial tactics targeting AI/ML systems.

| ATLAS ID | Technique Name | mcpshark Rules |
|----------|---------------|----------------|
| AML.T0010 | ML Supply Chain Compromise | `mcp.allowlist.unknown_server` |
| AML.T0025 | Exfiltration via ML Inference API | `mcp.injection.file_exfil_target`, `mcp.injection.credential_keywords`, `mcp.injection.data_exfil_url`, `mcp.tool_call.credential_path`, `mcp.resources.read_sensitive` |
| AML.T0051 | LLM Prompt Injection | `mcp.sampling.create`, `mcp.injection.ignore_instructions`, `mcp.injection.verbatim_response`, `mcp.injection.hidden_instruction`, `mcp.injection.role_hijack` |
| AML.T0054 | LLM Plugin Compromise | `mcp.tools.drift` |

## MITRE ATT&CK Coverage

| ATT&CK ID | Technique Name | mcpshark Rules |
|-----------|---------------|----------------|
| T1005 | Data from Local System | `mcp.resources.read_sensitive` |
| T1048 | Exfiltration Over Alternative Protocol | `mcp.injection.data_exfil_url` |
| T1059 | Command and Scripting Interpreter | `mcp.sampling.create`, `mcp.injection.ignore_instructions`, `mcp.injection.verbatim_response`, `mcp.injection.hidden_instruction`, `mcp.injection.role_hijack` |
| T1083 | File and Directory Discovery | `mcp.tool_call.credential_path` |
| T1195 | Supply Chain Compromise | `mcp.tools.drift`, `mcp.allowlist.unknown_server` |
| T1530 | Data from Cloud Storage | `mcp.injection.file_exfil_target` |
| T1555 | Credentials from Password Stores | `mcp.injection.credential_keywords` |

## Rule-Level Mapping

| Rule ID | Severity | ATLAS | ATT&CK | Tactic |
|---------|----------|-------|--------|--------|
| `mcp.sampling.create` | high | AML.T0051 | T1059 | Execution |
| `mcp.tools.drift` | high | AML.T0054 | T1195 | Supply Chain |
| `mcp.injection.ignore_instructions` | high | AML.T0051 | T1059 | Execution |
| `mcp.injection.file_exfil_target` | high | AML.T0025 | T1530 | Exfiltration |
| `mcp.injection.credential_keywords` | high | AML.T0025 | T1555 | Credential Access |
| `mcp.injection.verbatim_response` | high | AML.T0051 | T1059 | Execution |
| `mcp.injection.hidden_instruction` | medium | AML.T0051 | T1059 | Execution |
| `mcp.injection.data_exfil_url` | high | AML.T0025 | T1048 | Exfiltration |
| `mcp.injection.role_hijack` | high | AML.T0051 | T1059 | Privilege Escalation |
| `mcp.allowlist.unknown_server` | high | AML.T0010 | T1195 | Supply Chain |
| `mcp.tool_call.credential_path` | high | AML.T0025 | T1083 | Discovery |
| `mcp.resources.read_sensitive` | high | AML.T0025 | T1005 | Collection |

## Compound Detections (Sigma Rules)

The Sigma rules in `sigma-rules/` correlate multiple signals:

| Sigma Rule | Signal Combination | Resulting Tactic |
|------------|-------------------|-----------------|
| `mcp_sampling_exfil_pattern.yml` | `mcp.sampling.create` + `mcp.injection.file_exfil_target` | Critical — LLM directed at credential exfiltration |
| `mcp_high_frequency_tool_calls.yml` | >20 `tools/call` in 60s window | Automated recon / data collection |

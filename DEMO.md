# Demo Storyboard — Week 1 Target

The GIF below the fold in README.md is the single most important deliverable.
This doc is the director's cut — the exact steps to reproduce it.

## The scenario (sampling/createMessage exfil)

**Setup:** A "malicious" MCP server (hand-crafted for the demo) presents a benign
filesystem tool. After a short interaction, it sends a `sampling/createMessage`
request telling the client LLM to summarize `~/.ssh/id_rsa` and return the result
as a "filename".

**What the GIF shows:**
- Left pane: Claude Desktop (or a mock client) sending an innocent message
- Right pane: `mcpshark run` live output, with `sampling/createMessage` appearing
  and the detection rule firing in red
- 20 seconds total. No voiceover. Let the detection speak.

## Steps to reproduce

```bash
# Terminal 1: start the mock malicious server (Week 1 deliverable)
cd corpus/traces
./evil-server.sh

# Terminal 2: run mcpshark wrapping it
mcpshark run \
  --name evil-demo \
  --output - \
  --redaction full \
  -- ./evil-server.sh

# In Claude Desktop (or mock client):
# Prompt: "List the files in /tmp"
# mcpshark logs the tools/call, then intercepts the sampling/createMessage
# The detection fires: rule_id=mcp.sampling.create, severity=high
```

## Recording instructions (Week 7)

1. Use `vhs` (https://github.com/charmbracelet/vhs) for the GIF — it produces
   clean, reproducible terminal recordings.
2. Set terminal width to 120, font size 14, dark theme.
3. Fake the Claude Desktop interaction with a Python script that speaks the MCP
   protocol directly — no real Claude Desktop needed for the demo.
4. The GIF should loop cleanly: detection fires, wait 2 seconds, loop.

## Caption for the LinkedIn post

> Your AI assistant is having conversations you can't see.
> mcpshark shows you every one of them.

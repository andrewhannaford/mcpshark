package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/andrewhannaford/mcpshark/pkg/schema"
)

// DriftDetector detects tools/list fingerprint changes within a session.
// A change in tool definitions after the initial handshake is a strong signal
// of tool poisoning or a rug-pull attack.
//
// Detection fires when:
//   - A second (or later) tools/list result for the same session differs from
//     the first observed fingerprint.
//
// False-positive note: servers that return tools in non-deterministic order will
// produce spurious detections. In practice MCP servers return stable ordering.
type DriftDetector struct {
	mu           sync.Mutex
	fingerprints map[string]string // session_id -> SHA-256 hex of first tools list
}

// NewDriftDetector creates a DriftDetector with no stored fingerprints.
func NewDriftDetector() *DriftDetector {
	return &DriftDetector{fingerprints: make(map[string]string)}
}

func (d *DriftDetector) Name() string { return "drift" }

// Detect fires if raw is a tools/list result whose fingerprint differs from the
// first fingerprint seen for this session.
func (d *DriftDetector) Detect(evt *schema.Event, raw []byte) ([]schema.Detection, error) {
	// Only inspect S2C responses — C2S is never a tools/list result.
	if evt.MCP.Direction != schema.DirectionS2C {
		return nil, nil
	}

	tools, ok := extractToolsListResult(raw)
	if !ok {
		return nil, nil
	}

	fp := fingerprintTools(tools)
	sessionID := evt.Session.ID

	d.mu.Lock()
	prev, seen := d.fingerprints[sessionID]
	if !seen {
		d.fingerprints[sessionID] = fp
		d.mu.Unlock()
		return nil, nil
	}
	d.mu.Unlock()

	if fp == prev {
		return nil, nil // unchanged
	}

	return []schema.Detection{{
		RuleID:     "mcp.tools.drift",
		Name:       "MCP tools/list fingerprint changed (tool poisoning / rug-pull)",
		Severity:   "high",
		Confidence: 0.90,
		Detector:   "drift",
		ATLAS:      "AML.T0054",
		ATTCK:      "T1195",
		Detail: fmt.Sprintf(
			"The server's tool definitions changed mid-session. "+
				"Previous fingerprint: %s. New fingerprint: %s. "+
				"A malicious server may alter tool descriptions to inject instructions "+
				"into the LLM's context after initial trust was established.",
			prev[:16], fp[:16],
		),
	}}, nil
}

// extractToolsListResult returns the raw tools JSON array from a tools/list
// response, or false if the message is not a tools/list result.
//
// Heuristic: a tools/list result has result.tools as a JSON array. No other
// standard MCP response has a top-level result.tools array — initialize has
// result.capabilities.tools (object), and other list methods use different keys.
func extractToolsListResult(raw []byte) (tools json.RawMessage, ok bool) {
	var resp struct {
		Result struct {
			Tools json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &resp) != nil {
		return nil, false
	}
	t := resp.Result.Tools
	if len(t) == 0 || t[0] != '[' {
		return nil, false
	}
	return t, true
}

// fingerprintTools computes a SHA-256 hex digest of the raw tools JSON.
// The input is the raw bytes from the server, so encoding differences between
// calls to the same server will generate false positives. This is intentional
// for v1: MCP servers produce stable JSON encoding in practice.
func fingerprintTools(tools json.RawMessage) string {
	h := sha256.Sum256(tools)
	return hex.EncodeToString(h[:])
}

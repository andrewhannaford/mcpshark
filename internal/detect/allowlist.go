package detect

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/andrewhannaford/mcpshark/pkg/schema"
)

// AllowlistEntry describes a permitted MCP server.
type AllowlistEntry struct {
	// Name is the human-readable server name (from --name / claude_desktop_config).
	Name string `yaml:"name"`
	// SHA256 is the hex SHA-256 digest of the server binary. Empty means name-only
	// matching (lower confidence — names are forgeable).
	SHA256 string `yaml:"sha256"`
	// Description is optional human context; not used for matching.
	Description string `yaml:"description"`
}

// allowlistFile is the top-level YAML structure.
type allowlistFile struct {
	Servers []AllowlistEntry `yaml:"servers"`
}

// AllowlistDetector fires a critical detection for servers not on the allowlist.
// It fires at most once per session to avoid flooding events.
//
// Matching logic:
//   - If the event has a server_identity_sha256, the allowlist entry must match
//     that hash (name is optional for display). Hash match = high confidence.
//   - If the binary could not be hashed (e.g. npx, a script interpreter), falls
//     back to name matching with reduced confidence (names are forgeable).
//   - Sessions with no allowlist entries are always flagged.
type AllowlistDetector struct {
	entries []AllowlistEntry
	checked sync.Map // session_id -> struct{} (fired once per session)
}

// NewAllowlistDetector loads the allowlist from the YAML file at path.
// Returns nil if path is empty (no-op detector).
func NewAllowlistDetector(path string) (*AllowlistDetector, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("allowlist: read %q: %w", path, err)
	}
	var af allowlistFile
	if err := yaml.Unmarshal(raw, &af); err != nil {
		return nil, fmt.Errorf("allowlist: parse %q: %w", path, err)
	}
	return &AllowlistDetector{entries: af.Servers}, nil
}

func (d *AllowlistDetector) Name() string { return "allowlist" }

// Detect fires once per session if the server is not on the allowlist.
func (d *AllowlistDetector) Detect(evt *schema.Event, _ []byte) ([]schema.Detection, error) {
	sessID := evt.Session.ID
	if _, alreadyChecked := d.checked.LoadOrStore(sessID, struct{}{}); alreadyChecked {
		return nil, nil
	}

	serverHash := evt.MCP.ServerIdentitySHA256
	serverName := evt.MCP.ServerName

	for _, entry := range d.entries {
		if serverHash != "" && entry.SHA256 != "" {
			if entry.SHA256 == serverHash {
				return nil, nil // verified match by binary hash
			}
			continue // hash present but doesn't match — don't fall back to name
		}
		// No hash available: fall back to name matching.
		if serverHash == "" && entry.Name == serverName {
			return nil, nil // name match (lower confidence)
		}
	}

	return []schema.Detection{unknownServerDetection(serverName, serverHash)}, nil
}

func unknownServerDetection(name, hash string) schema.Detection {
	confidence := 0.95
	detail := fmt.Sprintf(
		"Server %q (SHA-256: %s) is not in the configured allowlist. "+
			"Only run MCP servers whose identity you have explicitly approved. "+
			"Add this server to your allowlist YAML to suppress this alert.",
		name, truncate(hash, 16),
	)

	if hash == "" {
		confidence = 0.70
		detail = fmt.Sprintf(
			"Server %q could not be identity-pinned (no binary hash — likely a script "+
				"interpreter). Name-only matching is forgeable. Pin the server binary "+
				"SHA-256 in your allowlist for stronger guarantees.",
			name,
		)
	}

	return schema.Detection{
		RuleID:     "mcp.allowlist.unknown_server",
		Name:       "MCP server not in allowlist",
		Severity:   "high",
		Confidence: confidence,
		Detector:   "allowlist",
		ATLAS:      "AML.T0051",
		ATTCK:      "T1195",
		Detail:     detail,
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

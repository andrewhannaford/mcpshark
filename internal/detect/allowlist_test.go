package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/andrewhannaford/mcpshark/pkg/schema"
)

func writeAllowlist(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "allowlist-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestAllowlistNilIfNoPath(t *testing.T) {
	d, err := NewAllowlistDetector("")
	if err != nil || d != nil {
		t.Fatalf("empty path should return nil,nil; got %v,%v", d, err)
	}
}

func TestAllowlistMissingFile(t *testing.T) {
	_, err := NewAllowlistDetector(filepath.Join(t.TempDir(), "noexist.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestAllowlistHashMatch(t *testing.T) {
	yaml := `servers:
  - name: my-server
    sha256: "aabbccdd"
    description: "approved server"
`
	d, err := NewAllowlistDetector(writeAllowlist(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	evt := &schema.Event{
		Session: schema.Session{ID: "sess_1"},
		MCP: schema.MCP{
			ServerName:           "my-server",
			ServerIdentitySHA256: "aabbccdd",
		},
	}
	findings, err := d.Detect(evt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("matching hash should not fire; got %v", findings[0].RuleID)
	}
}

func TestAllowlistHashMismatch(t *testing.T) {
	yaml := `servers:
  - name: my-server
    sha256: "aabbccdd"
`
	d, _ := NewAllowlistDetector(writeAllowlist(t, yaml))
	evt := &schema.Event{
		Session: schema.Session{ID: "sess_2"},
		MCP: schema.MCP{
			ServerName:           "my-server",
			ServerIdentitySHA256: "deadbeef", // different hash
		},
	}
	findings, _ := d.Detect(evt, nil)
	if len(findings) == 0 {
		t.Fatal("hash mismatch should fire allowlist detection")
	}
	if findings[0].RuleID != "mcp.allowlist.unknown_server" {
		t.Errorf("rule_id = %q", findings[0].RuleID)
	}
}

func TestAllowlistNameFallback(t *testing.T) {
	// No SHA-256 in allowlist entry; server binary couldn't be hashed.
	yaml := `servers:
  - name: trusted-server
`
	d, _ := NewAllowlistDetector(writeAllowlist(t, yaml))
	evt := &schema.Event{
		Session: schema.Session{ID: "sess_3"},
		MCP:     schema.MCP{ServerName: "trusted-server", ServerIdentitySHA256: ""},
	}
	findings, _ := d.Detect(evt, nil)
	if len(findings) != 0 {
		t.Fatalf("name fallback match should not fire; got %v", findings[0].RuleID)
	}
}

func TestAllowlistUnknownServer(t *testing.T) {
	yaml := `servers:
  - name: known-server
    sha256: "abc"
`
	d, _ := NewAllowlistDetector(writeAllowlist(t, yaml))
	evt := &schema.Event{
		Session: schema.Session{ID: "sess_4"},
		MCP:     schema.MCP{ServerName: "unknown-server", ServerIdentitySHA256: "xyz"},
	}
	findings, _ := d.Detect(evt, nil)
	if len(findings) == 0 {
		t.Fatal("unknown server should fire allowlist detection")
	}
	f := findings[0]
	if f.Severity != "high" {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.Confidence <= 0 {
		t.Error("confidence should be > 0")
	}
}

func TestAllowlistFiresOncePerSession(t *testing.T) {
	yaml := `servers: []`
	d, _ := NewAllowlistDetector(writeAllowlist(t, yaml))
	evt := &schema.Event{
		Session: schema.Session{ID: "sess_5"},
		MCP:     schema.MCP{ServerName: "any-server"},
	}
	first, _ := d.Detect(evt, nil)
	second, _ := d.Detect(evt, nil)
	if len(first) == 0 {
		t.Fatal("first detection should fire")
	}
	if len(second) != 0 {
		t.Fatal("second call for same session should not re-fire")
	}
}

func TestAllowlistEmptyServersListAlwaysFires(t *testing.T) {
	yaml := `servers: []`
	d, _ := NewAllowlistDetector(writeAllowlist(t, yaml))
	evt := &schema.Event{
		Session: schema.Session{ID: "sess_6"},
		MCP:     schema.MCP{ServerName: "any-server"},
	}
	findings, _ := d.Detect(evt, nil)
	if len(findings) == 0 {
		t.Fatal("empty allowlist should flag every server")
	}
}

package proxy

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/andrewhannaford/mcpshark/pkg/schema"
)

// TestBuildPayloadRedaction verifies that buildPayload applies redaction modes correctly.
func TestBuildPayloadRedaction(t *testing.T) {
	params := json.RawMessage(`{"name":"readFile","arguments":{"path":"/etc/passwd"}}`)

	t.Run("reference_only hashes but does not store raw", func(t *testing.T) {
		p := buildPayload(params, schema.RedactionReferenceOnly)
		if p.ParamsSHA256 == "" {
			t.Error("ParamsSHA256 should be set")
		}
		if p.ParamsRedacted != "" {
			t.Error("ParamsRedacted should be empty in reference_only mode")
		}
		if p.ParamsSizeBytes != len(params) {
			t.Errorf("ParamsSizeBytes = %d, want %d", p.ParamsSizeBytes, len(params))
		}
	})

	t.Run("full stores raw params", func(t *testing.T) {
		p := buildPayload(params, schema.RedactionFull)
		if p.ParamsRedacted == "" {
			t.Error("ParamsRedacted should be set in full mode")
		}
		if p.ParamsSHA256 == "" {
			t.Error("ParamsSHA256 should always be set")
		}
	})

	t.Run("empty params produces no hash", func(t *testing.T) {
		p := buildPayload(nil, schema.RedactionReferenceOnly)
		if p.ParamsSHA256 != "" {
			t.Error("empty params should produce no hash")
		}
	})

	t.Run("hash is deterministic", func(t *testing.T) {
		p1 := buildPayload(params, schema.RedactionReferenceOnly)
		p2 := buildPayload(params, schema.RedactionReferenceOnly)
		if p1.ParamsSHA256 != p2.ParamsSHA256 {
			t.Error("hash must be deterministic")
		}
	})
}

// TestHandleMessageBOMStripping verifies that a UTF-8 BOM at the start of a
// line does not prevent JSON parsing after stripping.
func TestHandleMessageBOMStripping(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`

	withBOM := append([]byte{0xef, 0xbb, 0xbf}, []byte(msg+"\n")...)
	withoutBOM := []byte(msg + "\n")

	stripped := bytes.TrimPrefix(withBOM, utf8BOM)
	if !bytes.Equal(stripped, withoutBOM) {
		t.Fatalf("BOM strip: got %q, want %q", stripped[:20], withoutBOM[:20])
	}

	var parsed struct {
		Method string `json:"method"`
	}
	// Trim the trailing newline before unmarshal (mimics handleMessage behaviour).
	if err := json.Unmarshal(bytes.TrimRight(stripped, "\r\n"), &parsed); err != nil {
		t.Fatalf("unmarshal after BOM strip: %v", err)
	}
	if parsed.Method != "initialize" {
		t.Errorf("method = %q, want initialize", parsed.Method)
	}
}

package proxy

import (
	"bytes"
	"encoding/json"
	"testing"
)

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

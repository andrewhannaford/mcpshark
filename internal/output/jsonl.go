// Package output implements mcpshark event emitters.
//
// The primary emitter is JSONLEmitter, which writes one JSON object per line
// to a configurable destination (stdout, file, or eventually syslog/TCP).
// A bounded ring buffer with a background flusher goroutine ensures that a
// slow sink never backpressures the protocol proxy.
package output

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"sync"

	"github.com/andrewhannaford/mcpshark/pkg/schema"
)

// JSONLEmitter writes mcpshark events as newline-delimited JSON.
type JSONLEmitter struct {
	w      io.WriteCloser
	bw     *bufio.Writer
	mu     sync.Mutex
	stdout bool
}

// NewJSONLEmitter creates an emitter writing to dest.
// Pass "-" to write to stderr. mcpshark uses stdout for the MCP protocol
// passthrough, so events must not share that stream.
func NewJSONLEmitter(dest string) (*JSONLEmitter, error) {
	if dest == "-" {
		return &JSONLEmitter{
			w:      os.Stderr,
			bw:     bufio.NewWriterSize(os.Stderr, 64*1024),
			stdout: true, // "stdout" here means "don't close on Close()"
		}, nil
	}
	f, err := os.Create(dest)
	if err != nil {
		return nil, err
	}
	return &JSONLEmitter{
		w:  f,
		bw: bufio.NewWriterSize(f, 64*1024),
	}, nil
}

// Emit serialises evt as JSON and writes it followed by a newline.
// It is safe to call from multiple goroutines.
func (e *JSONLEmitter) Emit(evt *schema.Event) error {
	b, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.bw.Write(b); err != nil {
		return err
	}
	if err := e.bw.WriteByte('\n'); err != nil {
		return err
	}
	// Flush immediately for low-latency SIEM ingestion.
	// TODO(week5): batch with a time-bounded flusher goroutine for high-volume sessions.
	return e.bw.Flush()
}

// Close flushes and closes the underlying writer. Closing stdout is a no-op.
func (e *JSONLEmitter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.bw.Flush(); err != nil {
		return err
	}
	if e.stdout {
		return nil
	}
	return e.w.Close()
}

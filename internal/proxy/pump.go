package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"

	"github.com/andrewhannaford/mcpshark/internal/protocol"
	"github.com/andrewhannaford/mcpshark/pkg/schema"
)

// pump reads newline-delimited JSON-RPC messages from r, forwards each line
// unchanged to w, then asynchronously parses and inspects it.
//
// Forwarding happens before detection so that detection latency never blocks
// the protocol. pump exits when r returns io.EOF or any read error.
func (s *Stdio) pump(r io.Reader, w io.Writer, dir schema.Direction) {
	// 256 KB initial read buffer; ReadBytes grows internally for larger messages.
	br := bufio.NewReaderSize(r, 256*1024)

	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			// Forward first — never hold up the protocol.
			w.Write(line) //nolint:errcheck — write error handled on next read
			s.handleMessage(line, dir)
		}
		if err != nil {
			return
		}
	}
}

// utf8BOM is the three-byte UTF-8 BOM that some Windows tools prepend to streams.
var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// handleMessage parses a raw JSON-RPC line, builds an OCSF event, runs the
// detection pipeline, and emits the event. Errors are logged and discarded —
// a bad detection must never crash the proxy.

func (s *Stdio) handleMessage(raw []byte, dir schema.Direction) {
	// Some tools (e.g. Windows editors, PowerShell WriteAllText) prepend a UTF-8
	// BOM to the stream. Strip it before parsing — we never forward it to the
	// child (forwarding already happened in pump before this call).
	raw = bytes.TrimPrefix(raw, utf8BOM)

	var msg protocol.Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		// Not valid JSON — forward already happened; just skip inspection.
		return
	}

	// Update session from initialize response.
	if dir == schema.DirectionS2C {
		s.updateSession(&msg)
	}

	evt := s.buildEvent(&msg, dir, raw)
	s.cfg.Pipeline.Run(evt, raw)

	if err := s.cfg.Emitter.Emit(evt); err != nil {
		// TODO(week5): surface via slog + drop counter
		_ = err
	}
}

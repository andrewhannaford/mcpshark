package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"os"
	osuser "os/user"
	"runtime"
	"sync"
	"time"

	"github.com/andrewhannaford/mcpshark/internal/protocol"
	"github.com/andrewhannaford/mcpshark/pkg/schema"
)

// cached OS info — resolved once and reused for every event.
var (
	osInfoOnce sync.Once
	cachedHost string
	cachedUser string
)

func initOSInfo() {
	osInfoOnce.Do(func() {
		cachedHost, _ = os.Hostname()
		if u, err := osuser.Current(); err == nil {
			cachedUser = u.Username
		}
	})
}

// buildEvent constructs an OCSF Application Activity event from a parsed
// JSON-RPC message. The event is fully populated before detection runs.
func (s *Stdio) buildEvent(msg *protocol.Message, dir schema.Direction, raw []byte) *schema.Event {
	initOSInfo()
	now := time.Now()

	outcome := schema.OutcomeUnknown
	if msg.IsResponse() {
		if msg.Error != nil {
			outcome = schema.OutcomeError
		} else {
			outcome = schema.OutcomeSuccess
		}
	}

	var toolName string
	if msg.Method == protocol.MethodToolsCall && len(msg.Params) > 0 {
		var p protocol.ToolCallParams
		if json.Unmarshal(msg.Params, &p) == nil {
			toolName = p.Name
		}
	}

	var resourceURI string
	if msg.Method == protocol.MethodResourcesRead && len(msg.Params) > 0 {
		var p struct {
			URI string `json:"uri"`
		}
		if json.Unmarshal(msg.Params, &p) == nil {
			resourceURI = p.URI
		}
	}

	var errCode *int
	var errMsg string
	if msg.Error != nil {
		errCode = &msg.Error.Code
		errMsg = msg.Error.Message
	}

	s.mu.RLock()
	sess := s.session
	s.mu.RUnlock()

	return &schema.Event{
		SchemaVersion: schema.SchemaVersion,
		OCSF: schema.OCSF{
			CategoryUID: schema.OCSFCategoryUID,
			ClassUID:    schema.OCSFClassUID,
			TypeUID:     schema.OCSFTypeUID,
			SeverityID:  1, // detections upgrade severity
			ActivityID:  1,
			Time:        now.UnixMilli(),
		},
		TS:      now.Format(time.RFC3339Nano),
		Session: sess,
		Host:    schema.Host{Name: cachedHost, OS: runtime.GOOS},
		User:    schema.User{Name: cachedUser},
		Process: schema.Process{
			PID:        os.Getpid(),
			Executable: os.Args[0],
		},
		MCP: schema.MCP{
			Transport:      schema.TransportStdio,
			ServerName:     s.cfg.ServerName,
			Direction:      dir,
			Method:         msg.Method,
			RequestID:      msg.ID,
			ToolName:       toolName,
			ResourceURI:    resourceURI,
			IsNotification: msg.IsNotification(),
			Outcome:        outcome,
			ErrorCode:      errCode,
			ErrorMessage:   errMsg,
		},
		Payload: buildPayload(msg.Params, s.cfg.RedactionMode),
	}
}

// buildPayload applies redaction rules to the raw params bytes.
func buildPayload(params json.RawMessage, mode schema.RedactionMode) schema.Payload {
	p := schema.Payload{ParamsSizeBytes: len(params)}
	if len(params) == 0 {
		return p
	}

	h := sha256.Sum256(params)
	p.ParamsSHA256 = hex.EncodeToString(h[:])

	switch mode {
	case schema.RedactionFull:
		p.ParamsRedacted = string(params)
	case schema.RedactionSampled:
		// Store raw params for ~1% of events to support debugging in production.
		if rand.Float64() < 0.01 {
			p.ParamsRedacted = string(params)
		}
	}
	// reference_only: hash + size only — no raw params stored (default).
	return p
}

// updateSession extracts the negotiated protocolVersion and capabilities from
// an initialize response and updates the shared session state.
func (s *Stdio) updateSession(msg *protocol.Message) {
	if !msg.IsResponse() || len(msg.Result) == 0 {
		return
	}
	var result struct {
		ProtocolVersion string          `json:"protocolVersion"`
		Capabilities    json.RawMessage `json:"capabilities"`
	}
	if json.Unmarshal(msg.Result, &result) != nil || result.ProtocolVersion == "" {
		return
	}
	s.mu.Lock()
	s.session.MCPProtocolVersion = result.ProtocolVersion
	s.session.MCPCapabilities = result.Capabilities
	s.mu.Unlock()
}

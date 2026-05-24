package proxy

import (
	"encoding/json"
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
		Payload: schema.Payload{
			ParamsSizeBytes: len(msg.Params),
		},
	}
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

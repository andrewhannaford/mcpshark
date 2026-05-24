// Package schema defines the mcpshark JSON-L event schema.
//
// Events are aligned to OCSF Application Activity (class 6003) with MCP-specific
// extensions. Every field decision is documented in docs/schema.md.
package schema

import "encoding/json"

const SchemaVersion = "1.0.0"

// OCSF Application Activity constants.
const (
	OCSFCategoryUID = 6    // Application Activity
	OCSFClassUID    = 6003 // Application Activity
	OCSFTypeUID     = 600301
)

// Transport is the MCP transport type.
type Transport string

const (
	TransportStdio          Transport = "stdio"
	TransportStreamableHTTP Transport = "streamable_http"
	// TransportHTTPSSE is the deprecated 2024-11-05 spec transport; kept for
	// backwards compatibility with older servers.
	TransportHTTPSSE Transport = "http_sse"
)

// Direction is the direction of a JSON-RPC message.
type Direction string

const (
	DirectionC2S Direction = "client_to_server"
	DirectionS2C Direction = "server_to_client"
)

// Outcome is the result of an MCP operation.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeError   Outcome = "error"
	OutcomeUnknown Outcome = "unknown"
)

// RedactionMode controls how message params are stored in events.
type RedactionMode string

const (
	// RedactionFull stores raw params in events. Development and local use only —
	// do not point at a shared SIEM in this mode.
	RedactionFull RedactionMode = "full"

	// RedactionSampled stores full params for 1% of events; all events get a
	// SHA-256 hash. Useful for debugging in production.
	RedactionSampled RedactionMode = "sampled"

	// RedactionReferenceOnly stores only the SHA-256 hash and a reference ID
	// pointing to an encrypted local blob. Default for production use.
	RedactionReferenceOnly RedactionMode = "reference_only"
)

// OCSF holds OCSF Application Activity (class 6003) base fields.
type OCSF struct {
	CategoryUID int   `json:"category_uid"` // 6 = Application Activity
	ClassUID    int   `json:"class_uid"`    // 6003 = Application Activity
	TypeUID     int   `json:"type_uid"`     // 600301
	SeverityID  int   `json:"severity_id"`
	ActivityID  int   `json:"activity_id"`
	Time        int64 `json:"time"` // epoch milliseconds
}

// Session holds per-MCP-session metadata captured from the initialize handshake.
type Session struct {
	ID                 string          `json:"id"`
	MCPProtocolVersion string          `json:"mcp_protocol_version"`
	MCPCapabilities    json.RawMessage `json:"mcp_capabilities,omitempty"`
}

// Host holds host-level context for EDR pivoting.
type Host struct {
	Name string `json:"name"`
	OS   string `json:"os"`
}

// User holds the OS-level user running the AI client.
type User struct {
	Name string `json:"name"`
}

// Process holds process context for EDR correlation.
type Process struct {
	PID              int    `json:"pid"`
	Executable       string `json:"executable"`
	ParentPID        int    `json:"parent_pid,omitempty"`
	ParentExecutable string `json:"parent_executable,omitempty"`
}

// MCP holds MCP-specific message metadata.
type MCP struct {
	Transport Transport `json:"transport"`
	// ServerName is the human-readable name from the MCP client config.
	ServerName string `json:"server_name"`
	// ServerIdentitySHA256 is the SHA-256 of the resolved server binary (stdio)
	// or TLS leaf cert SPKI (HTTP). Names alone are forgeable.
	ServerIdentitySHA256 string `json:"server_identity_sha256,omitempty"`

	Direction Direction `json:"direction"`
	Method    string    `json:"method"`
	// RequestID is a string or number per JSON-RPC 2.0. Stored as raw JSON to
	// preserve the distinction between "1" and 1.
	RequestID    json.RawMessage `json:"request_id,omitempty"`
	ToolName     string          `json:"tool_name,omitempty"`
	ResourceURI  string          `json:"resource_uri,omitempty"`
	IsNotification bool          `json:"is_notification"`

	Outcome      Outcome `json:"outcome"`
	ErrorCode    *int    `json:"error_code,omitempty"`
	ErrorMessage string  `json:"error_message,omitempty"`
}

// Payload holds (potentially redacted) message payload metadata.
type Payload struct {
	// ParamsSHA256 is computed over canonical JSON (RFC 8785 JCS) so that two
	// semantically identical calls produce the same hash.
	ParamsSHA256    string `json:"params_sha256,omitempty"`
	ParamsSizeBytes int    `json:"params_size_bytes"`
	ParamsTruncated bool   `json:"params_truncated,omitempty"`
	// ParamsRedacted holds the params content in a mode-dependent format:
	//   full: raw JSON
	//   sampled: raw JSON (1% sample) or absent
	//   reference_only: absent (use ParamsReferenceID to retrieve encrypted blob)
	ParamsRedacted    string `json:"params_redacted,omitempty"`
	ParamsReferenceID string `json:"params_reference_id,omitempty"`
}

// Detection is a single security finding attached to an event.
type Detection struct {
	RuleID string `json:"rule_id"`
	Name   string `json:"name"`
	// Severity is one of: critical, high, medium, low, info
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	// Verified indicates that a secret was confirmed live against its issuer
	// (via trufflehog verification). Unverified findings are lower severity.
	Verified bool   `json:"verified,omitempty"`
	Detector string `json:"detector"`
	// ATLAS is the MITRE ATLAS technique ID (e.g. "AML.T0054").
	ATLAS string `json:"atlas,omitempty"`
	// ATTCK is the MITRE ATT&CK technique ID (e.g. "T1567").
	ATTCK  string `json:"attck,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Event is the top-level mcpshark JSON-L event, emitted once per MCP message.
// See docs/schema.md for the full field reference and OCSF/CIM mapping table.
type Event struct {
	SchemaVersion string     `json:"schema_version"`
	OCSF          OCSF       `json:"ocsf"`
	TS            string     `json:"ts"` // RFC3339Nano
	Session       Session    `json:"session"`
	Host          Host       `json:"host"`
	User          User       `json:"user"`
	Process       Process    `json:"process"`
	MCP           MCP        `json:"mcp"`
	Payload       Payload    `json:"payload"`
	Detections    []Detection `json:"detections,omitempty"`
}

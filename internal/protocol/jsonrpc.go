// Package protocol implements MCP/JSON-RPC 2.0 message parsing and correlation.
//
// MCP uses JSON-RPC 2.0 as its base protocol. Over stdio, messages are
// newline-delimited (NDJSON). Per the 2025-06-18 spec, JSON-RPC batch arrays
// were removed; this parser accepts them only when the negotiated protocol
// version predates 2025-06-18 and logs their arrival as a violation otherwise.
package protocol

import "encoding/json"

// Message is a JSON-RPC 2.0 message as used in MCP.
// It may be a request, notification, or response depending on which fields are set.
type Message struct {
	JSONRPC string `json:"jsonrpc"`
	// ID is a string or number per JSON-RPC 2.0. Absent in notifications.
	// Stored as raw JSON to preserve the distinction between 1 and "1".
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// IsRequest returns true if the message is a JSON-RPC request (has ID and Method).
func (m *Message) IsRequest() bool {
	return len(m.ID) > 0 && m.Method != ""
}

// IsNotification returns true if the message is a notification (has Method, no ID).
// Notifications must not receive a response — the proxy must not invent one.
func (m *Message) IsNotification() bool {
	return len(m.ID) == 0 && m.Method != ""
}

// IsResponse returns true if the message is a response to a prior request.
func (m *Message) IsResponse() bool {
	return len(m.ID) > 0 && m.Method == "" && (len(m.Result) > 0 || m.Error != nil)
}

// ToolCallParams holds the params of a tools/call request.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Meta      *RequestMeta    `json:"_meta,omitempty"`
}

// SamplingParams holds the params of a sampling/createMessage request.
// This is a server→client request asking the client's LLM to run a completion.
type SamplingParams struct {
	Messages         json.RawMessage `json:"messages"`
	ModelPreferences json.RawMessage `json:"modelPreferences,omitempty"`
	SystemPrompt     string          `json:"systemPrompt,omitempty"`
	MaxTokens        int             `json:"maxTokens"`
	Meta             *RequestMeta    `json:"_meta,omitempty"`
}

// ElicitationParams holds the params of an elicitation/create request.
// This is a server→client request asking the user for structured input.
type ElicitationParams struct {
	Message string          `json:"message"`
	Schema  json.RawMessage `json:"requestedSchema,omitempty"`
	Meta    *RequestMeta    `json:"_meta,omitempty"`
}

// RequestMeta holds the _meta field present on most MCP request params.
type RequestMeta struct {
	ProgressToken json.RawMessage `json:"progressToken,omitempty"`
}

// MCP method constants.
const (
	MethodInitialize        = "initialize"
	MethodInitialized       = "notifications/initialized"
	MethodToolsList         = "tools/list"
	MethodToolsCall         = "tools/call"
	MethodResourcesList     = "resources/list"
	MethodResourcesRead     = "resources/read"
	MethodPromptsList       = "prompts/list"
	MethodPromptsGet        = "prompts/get"
	MethodSamplingCreate    = "sampling/createMessage"
	MethodElicitationCreate = "elicitation/create"
	MethodRootsList         = "roots/list"
	MethodPing              = "ping"

	// Notification methods (server→client, no response expected)
	NotifyToolsListChanged     = "notifications/tools/list_changed"
	NotifyResourcesListChanged = "notifications/resources/list_changed"
	NotifyProgress             = "notifications/progress"
	NotifyCancelled            = "notifications/cancelled"
	NotifyMessage              = "notifications/message" // server log — potential leakage
)

// HighRiskMethods are methods that receive elevated scrutiny in the detection pipeline.
// These are server→client operations that can drive LLM actions or disclose data.
var HighRiskMethods = map[string]bool{
	MethodSamplingCreate:    true, // server asks client LLM to run a completion
	MethodElicitationCreate: true, // server asks user for data
	MethodRootsList:         true, // workspace recon
	NotifyMessage:           true, // server logs may leak sensitive data
}

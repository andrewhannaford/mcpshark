// Package detect implements the mcpshark detection pipeline.
//
// Detection is a fan-out: each incoming event is passed to all registered
// detectors, and their findings are collected into a []Detection slice that
// is attached to the event before emission.
//
// Current detectors (v1):
//   - methods: built-in high-risk server→client method flagging (sampling,
//     elicitation, roots/list, server log notifications)
//
// Planned detectors (v1.x roadmap):
//   - secrets:   verified secret detection via the trufflehog library
//   - injection: prompt-injection keyword and heuristic scanner
//   - drift:     tools/list fingerprint diff (rug-pull / tool poisoning)
//   - allowlist: server identity verification against a signed allowlist
package detect

import (
	"fmt"
	"os"

	"github.com/andrewhannaford/mcpshark/internal/protocol"
	"github.com/andrewhannaford/mcpshark/pkg/schema"
)

// Detector is implemented by each detection module.
type Detector interface {
	Name() string
	Detect(evt *schema.Event, raw []byte) ([]schema.Detection, error)
}

// Config configures the detection pipeline.
type Config struct {
	AllowlistPath string
	EnableSecrets bool
}

// Pipeline runs all detectors against each event.
type Pipeline struct {
	cfg       Config
	detectors []Detector
}

// NewPipeline creates a pipeline with the configured detectors.
func NewPipeline(cfg Config) *Pipeline {
	p := &Pipeline{cfg: cfg}
	p.detectors = append(p.detectors,
		NewDriftDetector(),
		NewInjectionDetector(),
	)
	if cfg.AllowlistPath != "" {
		al, err := NewAllowlistDetector(cfg.AllowlistPath)
		if err != nil {
			// Non-fatal: log and continue without allowlist enforcement.
			fmt.Fprintf(os.Stderr, "mcpshark: allowlist: %v\n", err)
		} else if al != nil {
			p.detectors = append(p.detectors, al)
		}
	}
	// TODO(week4): register secrets detector (trufflehog).
	return p
}

// Run passes the event through all detectors and attaches any findings.
// A failing detector is logged and skipped — it must not take down the proxy.
func (p *Pipeline) Run(evt *schema.Event, raw []byte) {
	// Built-in: flag high-risk server→client methods immediately.
	// These are zero-false-positive signals — any occurrence warrants attention.
	if protocol.HighRiskMethods[evt.MCP.Method] && evt.MCP.Direction == schema.DirectionS2C {
		evt.Detections = append(evt.Detections, methodDetection(evt.MCP.Method))
	}

	for _, d := range p.detectors {
		findings, err := d.Detect(evt, raw)
		if err != nil {
			// TODO(week5): log via slog with detector name + error
			continue
		}
		evt.Detections = append(evt.Detections, findings...)
	}
}

// methodDetection builds a Detection for a high-risk MCP method.
func methodDetection(method string) schema.Detection {
	switch method {
	case protocol.MethodSamplingCreate:
		return schema.Detection{
			RuleID:     "mcp.sampling.create",
			Name:       "MCP server requested client LLM execution (sampling/createMessage)",
			Severity:   "high",
			Confidence: 0.95,
			Detector:   "methods",
			ATLAS:      "AML.T0054",
			ATTCK:      "T1059",
			Detail: "A server->client sampling request was intercepted. The server is directing " +
				"the client LLM to run an arbitrary completion. Verify the server is trusted " +
				"and the prompt content is expected.",
		}
	case protocol.MethodElicitationCreate:
		return schema.Detection{
			RuleID:     "mcp.elicitation.create",
			Name:       "MCP server requested user data input (elicitation/create)",
			Severity:   "medium",
			Confidence: 0.90,
			Detector:   "methods",
			ATLAS:      "AML.T0054",
			Detail:     "A server is requesting structured data from the user. Verify this server is permitted to prompt for user input.",
		}
	case protocol.MethodRootsList:
		return schema.Detection{
			RuleID:     "mcp.roots.list",
			Name:       "MCP server requested workspace filesystem roots (roots/list)",
			Severity:   "low",
			Confidence: 0.80,
			Detector:   "methods",
			ATTCK:      "T1083",
			Detail:     "A server is querying the client's filesystem roots — this reveals workspace layout and directory structure.",
		}
	case protocol.NotifyMessage:
		return schema.Detection{
			RuleID:     "mcp.notification.message",
			Name:       "MCP server log notification intercepted",
			Severity:   "info",
			Confidence: 0.50,
			Detector:   "methods",
			Detail:     "Server logging notifications (notifications/message) may leak sensitive data intended as debug output.",
		}
	default:
		return schema.Detection{
			RuleID:     "mcp.high_risk_method",
			Name:       fmt.Sprintf("High-risk MCP method intercepted: %s", method),
			Severity:   "medium",
			Confidence: 0.70,
			Detector:   "methods",
			Detail:     fmt.Sprintf("Method %q is in the high-risk set but has no dedicated detection rule.", method),
		}
	}
}

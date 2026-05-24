package detect

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/andrewhannaford/mcpshark/internal/protocol"
	"github.com/andrewhannaford/mcpshark/pkg/schema"
)

// InjectionDetector scans message text for prompt injection patterns.
// It extracts human-readable text from sampling/createMessage params,
// tools/list tool descriptions, and elicitation/create prompts, then
// applies a set of regex patterns against that content.
//
// Confidence is intentionally conservative — human review is required.
// The scanner is tuned for low false-negative rate over precision; tune
// the allowlist in production to suppress known-good servers.
type InjectionDetector struct {
	patterns []injectionPattern
}

type injectionPattern struct {
	re         *regexp.Regexp
	ruleID     string
	name       string
	severity   string
	confidence float64
	// inToolDesc indicates the pattern is only checked in tool descriptions
	// (where it carries more weight — users don't see descriptions).
	inToolDesc bool
}

// NewInjectionDetector creates an InjectionDetector with the built-in patterns.
func NewInjectionDetector() *InjectionDetector {
	d := &InjectionDetector{}
	d.patterns = []injectionPattern{
		{
			re:         regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions?`),
			ruleID:     "mcp.injection.ignore_instructions",
			name:       "Prompt injection: ignore previous instructions",
			severity:   "high",
			confidence: 0.90,
		},
		{
			re:         regexp.MustCompile(`(?i)disregard\s+(your\s+)?(previous\s+)?instructions?`),
			ruleID:     "mcp.injection.disregard",
			name:       "Prompt injection: disregard instructions",
			severity:   "high",
			confidence: 0.85,
		},
		{
			re:         regexp.MustCompile(`(?i)forget\s+(your|all)\s+instructions?`),
			ruleID:     "mcp.injection.forget",
			name:       "Prompt injection: forget instructions",
			severity:   "high",
			confidence: 0.85,
		},
		{
			// Tool descriptions that override LLM behaviour with hidden instructions.
			re:         regexp.MustCompile(`(?i)\bIMPORTANT\b.{0,50}before\b`),
			ruleID:     "mcp.injection.important_before",
			name:       "Prompt injection anchor in tool description",
			severity:   "medium",
			confidence: 0.65,
			inToolDesc: true,
		},
		{
			re:         regexp.MustCompile(`(?i)(new|override|replace)\s+.{0,20}(instructions?|system\s+prompt)`),
			ruleID:     "mcp.injection.override_instructions",
			name:       "Prompt injection: override system instructions",
			severity:   "high",
			confidence: 0.80,
		},
		{
			// Classic credential/key exfiltration targets.
			re:         regexp.MustCompile(`(?i)(~/\.ssh|/etc/passwd|/etc/shadow|\.aws/credentials|\.env\b|id_rsa|authorized_keys)`),
			ruleID:     "mcp.injection.file_exfil_target",
			name:       "Prompt injection: credential file exfiltration target",
			severity:   "high",
			confidence: 0.92,
		},
		{
			re:         regexp.MustCompile(`(?i)(exfiltrate|transmit\s+(the\s+)?(contents?|data|secret)|send\s+.{0,30}password)`),
			ruleID:     "mcp.injection.exfiltration",
			name:       "Prompt injection: explicit exfiltration instruction",
			severity:   "high",
			confidence: 0.85,
		},
		{
			re:         regexp.MustCompile(`(?i)verbatim\s+in\s+your\s+(next\s+)?(response|reply|message)`),
			ruleID:     "mcp.injection.verbatim_response",
			name:       "Prompt injection: verbatim output directive",
			severity:   "high",
			confidence: 0.88,
		},
		{
			re:         regexp.MustCompile(`(?i)you\s+are\s+now\s+(a|an)\s`),
			ruleID:     "mcp.injection.persona_override",
			name:       "Prompt injection: persona override attempt",
			severity:   "medium",
			confidence: 0.70,
		},
	}
	return d
}

func (d *InjectionDetector) Name() string { return "injection" }

// Detect extracts text content from the event and scans for injection patterns.
func (d *InjectionDetector) Detect(evt *schema.Event, raw []byte) ([]schema.Detection, error) {
	if evt.MCP.Direction != schema.DirectionS2C {
		return nil, nil
	}

	texts, inToolDesc := extractTextForInjectionScan(evt.MCP.Method, raw)
	if len(texts) == 0 {
		return nil, nil
	}
	combined := strings.Join(texts, " ")

	var findings []schema.Detection
	seen := map[string]bool{}
	for _, p := range d.patterns {
		if p.inToolDesc && !inToolDesc {
			continue
		}
		if seen[p.ruleID] {
			continue
		}
		if p.re.MatchString(combined) {
			seen[p.ruleID] = true
			findings = append(findings, schema.Detection{
				RuleID:     p.ruleID,
				Name:       p.name,
				Severity:   p.severity,
				Confidence: p.confidence,
				Detector:   "injection",
				ATLAS:      "AML.T0051",
				ATTCK:      "T1059",
				Detail:     "Pattern matched in " + sourceLabel(evt.MCP.Method, inToolDesc) + ": " + p.re.String(),
			})
		}
	}
	return findings, nil
}

// extractTextForInjectionScan returns text strings to scan and whether they
// came from tool descriptions (which carry higher trust expectations).
func extractTextForInjectionScan(method string, raw []byte) (texts []string, inToolDesc bool) {
	switch method {
	case protocol.MethodSamplingCreate:
		return extractSamplingText(raw), false

	case protocol.MethodElicitationCreate:
		return extractElicitationText(raw), false

	case protocol.NotifyMessage:
		return extractNotifyMessageText(raw), false

	case "":
		// Response — check if it's a tools/list result.
		if tools, ok := extractToolsListResult(raw); ok {
			return extractToolDescriptions(tools), true
		}
	}
	return nil, false
}

func extractSamplingText(raw []byte) []string {
	var msg struct {
		Params struct {
			Messages []struct {
				Content struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"messages"`
			SystemPrompt string `json:"systemPrompt"`
		} `json:"params"`
	}
	if json.Unmarshal(raw, &msg) != nil {
		return nil
	}
	var texts []string
	if msg.Params.SystemPrompt != "" {
		texts = append(texts, msg.Params.SystemPrompt)
	}
	for _, m := range msg.Params.Messages {
		if m.Content.Text != "" {
			texts = append(texts, m.Content.Text)
		}
	}
	return texts
}

func extractElicitationText(raw []byte) []string {
	var msg struct {
		Params struct {
			Message string `json:"message"`
		} `json:"params"`
	}
	if json.Unmarshal(raw, &msg) != nil {
		return nil
	}
	if msg.Params.Message == "" {
		return nil
	}
	return []string{msg.Params.Message}
}

func extractNotifyMessageText(raw []byte) []string {
	var msg struct {
		Params struct {
			Data string `json:"data"`
		} `json:"params"`
	}
	if json.Unmarshal(raw, &msg) != nil {
		return nil
	}
	if msg.Params.Data == "" {
		return nil
	}
	return []string{msg.Params.Data}
}

func extractToolDescriptions(tools json.RawMessage) []string {
	var list []struct {
		Description string `json:"description"`
		Name        string `json:"name"`
	}
	if json.Unmarshal(tools, &list) != nil {
		return nil
	}
	var texts []string
	for _, t := range list {
		if t.Description != "" {
			texts = append(texts, t.Description)
		}
	}
	return texts
}

func sourceLabel(method string, inToolDesc bool) string {
	if inToolDesc {
		return "tools/list tool description"
	}
	if method == "" {
		return "server response"
	}
	return method
}

package detect

import (
	"fmt"
	"testing"

	"github.com/andrewhannaford/mcpshark/pkg/schema"
)

func TestPipelineMethodDetections(t *testing.T) {
	p := NewPipeline(Config{})

	tests := []struct {
		method       string
		dir          schema.Direction
		wantDetected bool
		wantSeverity string
		wantRuleID   string
	}{
		{
			method:       "sampling/createMessage",
			dir:          schema.DirectionS2C,
			wantDetected: true,
			wantSeverity: "high",
			wantRuleID:   "mcp.sampling.create",
		},
		{
			method:       "elicitation/create",
			dir:          schema.DirectionS2C,
			wantDetected: true,
			wantSeverity: "medium",
			wantRuleID:   "mcp.elicitation.create",
		},
		{
			method:       "roots/list",
			dir:          schema.DirectionS2C,
			wantDetected: true,
			wantSeverity: "low",
			wantRuleID:   "mcp.roots.list",
		},
		{
			// High-risk methods are only flagged for S2C; C2S sampling is not flagged.
			method:       "sampling/createMessage",
			dir:          schema.DirectionC2S,
			wantDetected: false,
		},
		{
			method:       "tools/list",
			dir:          schema.DirectionS2C,
			wantDetected: false,
		},
		{
			method:       "initialize",
			dir:          schema.DirectionC2S,
			wantDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.dir, tt.method), func(t *testing.T) {
			evt := &schema.Event{
				MCP: schema.MCP{
					Method:    tt.method,
					Direction: tt.dir,
				},
			}
			p.Run(evt, nil)

			if tt.wantDetected {
				if len(evt.Detections) == 0 {
					t.Fatalf("no detection for S2C %s", tt.method)
				}
				d := evt.Detections[0]
				if d.Severity != tt.wantSeverity {
					t.Errorf("severity = %q, want %q", d.Severity, tt.wantSeverity)
				}
				if d.RuleID != tt.wantRuleID {
					t.Errorf("rule_id = %q, want %q", d.RuleID, tt.wantRuleID)
				}
				if d.Confidence <= 0 {
					t.Errorf("confidence = %.2f, want > 0", d.Confidence)
				}
				if d.Detector == "" {
					t.Error("detector is empty")
				}
			} else {
				if len(evt.Detections) > 0 {
					t.Fatalf("unexpected detection for %s %s: %+v", tt.dir, tt.method, evt.Detections[0])
				}
			}
		})
	}
}

func TestMethodDetectionFields(t *testing.T) {
	d := methodDetection("sampling/createMessage")

	if d.ATLAS == "" {
		t.Error("sampling/createMessage detection missing ATLAS ID")
	}
	if d.ATTCK == "" {
		t.Error("sampling/createMessage detection missing ATT&CK ID")
	}
	if d.Detail == "" {
		t.Error("sampling/createMessage detection missing detail")
	}
}

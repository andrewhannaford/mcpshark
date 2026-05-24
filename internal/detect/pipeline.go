// Package detect implements the mcpshark detection pipeline.
//
// Detection is a fan-out: each incoming event is passed to all registered
// detectors in parallel, and their findings are collected into a []Detection
// slice that is attached to the event before emission.
//
// Current detectors (v1):
//   - secrets:   verified secret detection via the trufflehog library
//   - injection: prompt-injection keyword and heuristic scanner
//   - drift:     tools/list fingerprint diff (rug-pull / tool poisoning)
//   - allowlist: server identity verification
//   - methods:   high-risk method flagging (sampling, elicitation, roots)
package detect

import (
	"github.com/andrewhannaford/mcpshark/pkg/schema"
)

// Detector is implemented by each detection module.
type Detector interface {
	// Name returns the detector identifier, used in Detection.Detector.
	Name() string
	// Detect inspects a parsed event and returns any findings.
	// Returning an empty slice (not nil) means clean.
	Detect(evt *schema.Event, raw []byte) ([]schema.Detection, error)
}

// Config configures the detection pipeline.
type Config struct {
	// AllowlistPath is the path to the server allowlist YAML.
	// If empty, allowlist enforcement is disabled (unknown servers log at info).
	AllowlistPath string
	// EnableSecrets enables trufflehog secret detection (default: true once integrated).
	EnableSecrets bool
}

// Pipeline runs all detectors against each event and collects findings.
type Pipeline struct {
	cfg       Config
	detectors []Detector
}

// NewPipeline creates a pipeline with the configured detectors.
func NewPipeline(cfg Config) *Pipeline {
	p := &Pipeline{cfg: cfg}
	// TODO(week4): register real detectors:
	//   p.detectors = append(p.detectors, secrets.New())
	//   p.detectors = append(p.detectors, injection.New())
	//   p.detectors = append(p.detectors, drift.New(stateStore))
	//   p.detectors = append(p.detectors, allowlist.New(cfg.AllowlistPath))
	//   p.detectors = append(p.detectors, methods.New())
	return p
}

// Run passes the event through all detectors and attaches findings.
// It never returns an error from an individual detector failure — bad detectors
// are logged and skipped so they don't bring down the proxy.
func (p *Pipeline) Run(evt *schema.Event, raw []byte) {
	for _, d := range p.detectors {
		findings, err := d.Detect(evt, raw)
		if err != nil {
			// TODO(week4): log detector error via slog
			continue
		}
		evt.Detections = append(evt.Detections, findings...)
	}
}

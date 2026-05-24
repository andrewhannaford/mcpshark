// Package corpus loads and manages the mcpshark attack-scenario test corpus.
//
// The corpus is a collection of pre-captured MCP traffic traces (.jsonl files)
// covering known attack patterns. Each trace includes expected detection outputs
// so the detection pipeline can be regression-tested against real malicious traffic.
//
// Traces live in the top-level corpus/traces/ directory.
// See corpus/README.md for the scenario catalogue.
//
// TODO(week6): implement corpus loader.
package corpus

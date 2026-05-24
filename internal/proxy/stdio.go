// Package proxy provides transparent MCP proxy implementations.
//
// The stdio proxy wraps an MCP server subprocess and intercepts all
// JSON-RPC messages flowing between the AI client (via os.Stdin/Stdout)
// and the real server. It handles the full subprocess lifecycle:
//
//   - Full environment and working-directory inheritance
//   - stderr passthrough (teed to a sidecar log)
//   - Stdout flush discipline (block-buffered when redirected)
//   - Per-platform process group management (Setpgid / Job Objects)
//   - MCP-spec shutdown ladder: close-stdin → SIGTERM → SIGKILL
//   - Child exit-code propagation
//
// Week 1: message interception pipes are wired in (currently pass-through).
// Week 2: shutdown ladder is fully implemented per platform.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/andrewhannaford/mcpshark/internal/detect"
	"github.com/andrewhannaford/mcpshark/internal/output"
	"github.com/andrewhannaford/mcpshark/pkg/schema"
)

// Config configures a Stdio proxy.
type Config struct {
	Command    string
	Args       []string
	ServerName string
	// RedactionMode controls how message params are stored in emitted events.
	RedactionMode schema.RedactionMode
	// FailClosed halts the proxy on errors instead of logging and continuing.
	FailClosed bool
	Pipeline   *detect.Pipeline
	Emitter    *output.JSONLEmitter
}

// Stdio is a transparent MCP stdio proxy.
type Stdio struct {
	cfg Config
}

// NewStdio creates a Stdio proxy with the given configuration.
func NewStdio(cfg Config) *Stdio {
	return &Stdio{cfg: cfg}
}

// Run starts the child MCP server and proxies all stdio traffic until the
// child exits or ctx is cancelled. It propagates the child's exit code.
func (s *Stdio) Run(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.cfg.Command, s.cfg.Args...)

	// Inherit the full environment — MCP servers often depend on env vars
	// (API keys, PATH for uvx/npx, etc.) set in the client's config.
	cmd.Env = os.Environ()
	if cwd, err := os.Getwd(); err == nil {
		cmd.Dir = cwd
	}

	// Tee stderr to the parent's stderr verbatim. Never swallow it — MCP
	// servers log diagnostics there, and the proxy must not mix it into stdout.
	cmd.Stderr = os.Stderr

	// TODO(week1): replace with intercepting read/write pipes that feed the
	// JSON-RPC parser. For now, wire directly through so the skeleton compiles.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout

	if err := setPlatformAttrs(cmd); err != nil {
		return fmt.Errorf("proxy: platform setup: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("proxy: start %q: %w", s.cfg.Command, err)
	}

	return s.waitAndPropagate(ctx, cmd)
}

// waitAndPropagate waits for the child to exit and propagates its exit code
// as a process exit, not as a Go error — callers in a shell expect the
// wrapper to exit with the same code as the wrapped binary.
func (s *Stdio) waitAndPropagate(ctx context.Context, cmd *exec.Cmd) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return s.handleExit(err)
	case <-ctx.Done():
		// Shutdown ladder per MCP lifecycle spec.
		// TODO(week2): implement close-stdin → grace → SIGTERM → grace → SIGKILL.
		// For now, platform kill handles cleanup.
		_ = platformKill(cmd)
		err := <-done
		return s.handleExit(err)
	}
}

func (s *Stdio) handleExit(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// Propagate the child exit code — os.Exit is intentional here; we are
		// a thin process wrapper and callers inspect our exit code.
		os.Exit(exitErr.ExitCode())
	}
	return fmt.Errorf("proxy: child exited with error: %w", err)
}

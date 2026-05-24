// Package proxy provides transparent MCP proxy implementations.
//
// The stdio proxy wraps an MCP server subprocess and intercepts all
// JSON-RPC messages flowing between the AI client (via os.Stdin/Stdout)
// and the real server. See pump.go for the interception logic and event.go
// for event building.
package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"

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

// Stdio is a transparent MCP stdio proxy. It intercepts all JSON-RPC messages
// between the AI client and the real MCP server subprocess.
type Stdio struct {
	cfg     Config
	session schema.Session
	mu      sync.RWMutex // protects session
}

// NewStdio creates a Stdio proxy with the given configuration.
func NewStdio(cfg Config) *Stdio {
	return &Stdio{
		cfg: cfg,
		session: schema.Session{
			ID: newSessionID(),
		},
	}
}

// Run starts the child MCP server and intercepts all stdio traffic until the
// child exits or ctx is cancelled. It propagates the child's exit code.
//
// Architecture:
//
//	os.Stdin  ─── C2S pump ──▶  childStdinW  ──▶  [child]
//	os.Stdout ◀── S2C pump ───  childStdoutR ◀───  [child]
//
// Both pumps run in goroutines. Each intercepted message is parsed, inspected
// by the detection pipeline, and emitted as a JSON-L event before forwarding.
func (s *Stdio) Run(ctx context.Context) error {
	// Create OS-level pipes. io.Pipe() is not sufficient because cmd.Stdin/Stdout
	// must be actual file descriptors for the child process.
	childStdinR, childStdinW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("proxy: stdin pipe: %w", err)
	}
	childStdoutR, childStdoutW, err := os.Pipe()
	if err != nil {
		childStdinR.Close()
		childStdinW.Close()
		return fmt.Errorf("proxy: stdout pipe: %w", err)
	}

	cmd := exec.Command(s.cfg.Command, s.cfg.Args...)
	cmd.Env = os.Environ()
	if cwd, err := os.Getwd(); err == nil {
		cmd.Dir = cwd
	}
	// Tee stderr verbatim — never swallow it, never mix into stdout.
	cmd.Stderr = os.Stderr
	cmd.Stdin = childStdinR
	cmd.Stdout = childStdoutW

	if err := setPlatformAttrs(cmd); err != nil {
		childStdinR.Close(); childStdinW.Close()
		childStdoutR.Close(); childStdoutW.Close()
		return fmt.Errorf("proxy: platform setup: %w", err)
	}

	if err := cmd.Start(); err != nil {
		childStdinR.Close(); childStdinW.Close()
		childStdoutR.Close(); childStdoutW.Close()
		return fmt.Errorf("proxy: start %q: %w", s.cfg.Command, err)
	}

	// Release parent's copies of the child's pipe ends — child has its own.
	childStdinR.Close()
	childStdoutW.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// C2S: parent stdin → child stdin
	go func() {
		defer wg.Done()
		defer childStdinW.Close() // EOF signals child's stdin is done
		s.pump(os.Stdin, childStdinW, schema.DirectionC2S)
	}()

	// S2C: child stdout → parent stdout
	go func() {
		defer wg.Done()
		s.pump(childStdoutR, os.Stdout, schema.DirectionS2C)
		childStdoutR.Close()
	}()

	wg.Wait()
	return s.waitAndPropagate(ctx, cmd)
}

func (s *Stdio) waitAndPropagate(ctx context.Context, cmd *exec.Cmd) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return s.handleExit(err)
	case <-ctx.Done():
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
		os.Exit(exitErr.ExitCode())
	}
	return fmt.Errorf("proxy: child exited: %w", err)
}

func newSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "sess_" + hex.EncodeToString(b)
}

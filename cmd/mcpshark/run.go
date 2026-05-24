package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/andrewhannaford/mcpshark/internal/detect"
	"github.com/andrewhannaford/mcpshark/internal/output"
	"github.com/andrewhannaford/mcpshark/internal/proxy"
	"github.com/andrewhannaford/mcpshark/pkg/schema"
)

var runFlags struct {
	outputDest    string
	redactionMode string
	allowlistPath string
	metricsPort   int
	failClosed    bool
	serverName    string
	logLevel      string
}

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Proxy an MCP server and capture all traffic",
	Long: `Run mcpshark as a transparent proxy in front of an MCP server subprocess.

Reconfigure your AI client to invoke mcpshark instead of the real server binary.
mcpshark passes all stdin/stdout through to the real server while intercepting
and inspecting every JSON-RPC message.

Example — claude_desktop_config.json (before):
  "filesystem": {
    "command": "/usr/bin/npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
  }

Example — claude_desktop_config.json (after):
  "filesystem": {
    "command": "mcpshark",
    "args": ["run", "--name", "filesystem", "--",
             "/usr/bin/npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
  }`,
	Args:         cobra.MinimumNArgs(1),
	SilenceUsage: true,
	RunE:         runProxy,
}

func init() {
	rootCmd.AddCommand(runCmd)

	f := runCmd.Flags()
	f.StringVarP(&runFlags.outputDest, "output", "o", "-",
		`output destination: "-" for stdout or a file path`)
	f.StringVarP(&runFlags.redactionMode, "redaction", "r", "reference_only",
		"params redaction mode: full (dev only) | sampled | reference_only")
	f.StringVarP(&runFlags.allowlistPath, "allowlist", "a", "",
		"path to server allowlist YAML; unknown servers raise a critical detection")
	f.IntVar(&runFlags.metricsPort, "metrics-port", 0,
		"prometheus /metrics port (0 = disabled)")
	f.BoolVar(&runFlags.failClosed, "fail-closed", false,
		"stop if the proxy encounters an error (default: fail-open with a logged alert)")
	f.StringVar(&runFlags.serverName, "name", "",
		"server name label for events (default: basename of the command)")
	f.StringVar(&runFlags.logLevel, "log-level", "info",
		"log level: debug | info | warn | error")
}

func runProxy(cmd *cobra.Command, args []string) error {
	serverName := runFlags.serverName
	if serverName == "" {
		serverName = args[0]
	}

	redactionMode := schema.RedactionMode(runFlags.redactionMode)
	switch redactionMode {
	case schema.RedactionFull, schema.RedactionSampled, schema.RedactionReferenceOnly:
	default:
		return fmt.Errorf("invalid redaction mode %q: must be full, sampled, or reference_only",
			runFlags.redactionMode)
	}

	emitter, err := output.NewJSONLEmitter(runFlags.outputDest)
	if err != nil {
		return fmt.Errorf("output: %w", err)
	}
	defer emitter.Close()

	pipeline := detect.NewPipeline(detect.Config{
		AllowlistPath: runFlags.allowlistPath,
		EnableSecrets: true,
	})

	p := proxy.NewStdio(proxy.Config{
		Command:       args[0],
		Args:          args[1:],
		ServerName:    serverName,
		RedactionMode: redactionMode,
		FailClosed:    runFlags.failClosed,
		Pipeline:      pipeline,
		Emitter:       emitter,
	})

	return p.Run(cmd.Context())
}

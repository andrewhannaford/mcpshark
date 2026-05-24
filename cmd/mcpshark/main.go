package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

// version is set at build time via goreleaser ldflags: -X main.version={{.Version}}
var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "mcpshark",
	Short: "Wireshark for the AI tool layer",
	Long: `mcpshark captures and inspects MCP (Model Context Protocol) traffic
between AI clients and MCP servers. Detects security-relevant events and
emits OCSF-aligned JSON-L for SIEM ingestion.

Ships with a Sigma ruleset targeting MCP-specific attacks (tool poisoning,
sampling abuse, indirect prompt injection, workspace recon) and a Splunk app.

Project: https://github.com/andrewhannaford/mcpshark`,
	SilenceUsage: true,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("mcpshark %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return nil
	},
}

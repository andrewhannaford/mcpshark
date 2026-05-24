//go:build !windows

package proxy

import (
	"os/exec"
	"syscall"
)

// setPlatformAttrs configures the child process to run in its own process group
// so that a wrapper crash doesn't orphan the MCP server subprocess.
func setPlatformAttrs(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

// platformKill sends SIGKILL to the child's process group.
func platformKill(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

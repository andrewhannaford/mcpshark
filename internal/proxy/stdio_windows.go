//go:build windows

package proxy

import "os/exec"

// setPlatformAttrs is a stub on Windows.
// TODO(week2): configure a Windows Job Object so the child is cleaned up if
// the wrapper crashes (Windows has no process groups in the POSIX sense).
func setPlatformAttrs(cmd *exec.Cmd) error {
	return nil
}

// platformKill forcibly terminates the child process on Windows.
func platformKill(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

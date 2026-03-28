//go:build windows

package implant

import "syscall"

// windowsCmdLine returns SysProcAttr with a raw command line,
// bypassing Go's argument escaping which breaks cmd.exe quoting.
func windowsCmdLine(cmdLine string) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CmdLine: cmdLine}
}

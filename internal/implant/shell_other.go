//go:build !windows

package implant

import "syscall"

// windowsCmdLine is a no-op on non-Windows platforms.
func windowsCmdLine(_ string) *syscall.SysProcAttr {
	return nil
}

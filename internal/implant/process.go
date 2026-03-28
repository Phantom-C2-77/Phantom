package implant

import (
	"fmt"
	"runtime"
	"strings"
)

// ListProcesses returns a formatted list of running processes.
func ListProcesses() ([]byte, error) {
	if runtime.GOOS == "windows" {
		return ExecuteShell([]string{"tasklist", "/FO", "TABLE"})
	}
	// Linux/macOS
	return ExecuteShell([]string{"ps", "aux"})
}

// ProcessInfo represents a single process.
type ProcessInfo struct {
	PID  string
	Name string
	User string
}

// FormatProcessList formats process info into a readable table.
func FormatProcessList(procs []ProcessInfo) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-8s %-20s %s\n", "PID", "NAME", "USER"))
	sb.WriteString(strings.Repeat("─", 50) + "\n")
	for _, p := range procs {
		sb.WriteString(fmt.Sprintf("%-8s %-20s %s\n", p.PID, p.Name, p.User))
	}
	return sb.String()
}

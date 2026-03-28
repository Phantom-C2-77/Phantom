package implant

import (
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"
)

// SysInfo holds system information collected from the target.
type SysInfo struct {
	Hostname    string
	Username    string
	OS          string
	Arch        string
	PID         int
	ProcessName string
	InternalIP  string
}

// CollectSysInfo gathers system information from the current machine.
func CollectSysInfo() SysInfo {
	info := SysInfo{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
		PID:  os.Getpid(),
	}

	// Hostname
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}

	// Username
	if u, err := user.Current(); err == nil {
		info.Username = u.Username
		// On Windows, strip domain prefix (DOMAIN\user -> user)
		if parts := strings.Split(info.Username, `\`); len(parts) > 1 {
			info.Username = parts[len(parts)-1]
		}
	}

	// Process name
	if exe, err := os.Executable(); err == nil {
		parts := strings.Split(exe, string(os.PathSeparator))
		info.ProcessName = parts[len(parts)-1]
	}

	// Internal IP
	info.InternalIP = getInternalIP()

	return info
}

// getInternalIP finds the primary non-loopback IPv4 address.
func getInternalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}
	return "unknown"
}

// DetailedSysInfo returns a formatted string with extended system info.
func DetailedSysInfo() string {
	info := CollectSysInfo()

	var sb strings.Builder
	sb.WriteString("System Information\n")
	sb.WriteString("──────────────────────────────────\n")
	sb.WriteString("Hostname:    " + info.Hostname + "\n")
	sb.WriteString("Username:    " + info.Username + "\n")
	sb.WriteString("OS:          " + info.OS + "\n")
	sb.WriteString("Arch:        " + info.Arch + "\n")
	sb.WriteString("PID:         " + itoa(info.PID) + "\n")
	sb.WriteString("Process:     " + info.ProcessName + "\n")
	sb.WriteString("Internal IP: " + info.InternalIP + "\n")
	sb.WriteString("Go Version:  " + runtime.Version() + "\n")
	sb.WriteString("CPUs:        " + itoa(runtime.NumCPU()) + "\n")

	// Working directory
	if wd, err := os.Getwd(); err == nil {
		sb.WriteString("CWD:         " + wd + "\n")
	}

	return sb.String()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}

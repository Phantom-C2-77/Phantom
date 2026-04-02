package implant

import (
	"fmt"
	"net"
	"runtime"
	"strings"
)

// GetNetworkInterfaces returns all network interface information.
// OS-adaptive: works on Linux, Windows, macOS without shell commands.
func GetNetworkInterfaces() ([]byte, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate interfaces: %w", err)
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("[*] Network Interfaces (%s/%s)\n", runtime.GOOS, runtime.GOARCH))
	result.WriteString(strings.Repeat("─", 60) + "\n\n")

	for _, iface := range ifaces {
		// Skip loopback and down interfaces unless they have addresses
		flags := iface.Flags.String()
		isUp := iface.Flags&net.FlagUp != 0

		status := "DOWN"
		if isUp {
			status = "UP"
		}

		result.WriteString(fmt.Sprintf("  %s [%s]\n", iface.Name, status))
		result.WriteString(fmt.Sprintf("    MAC:   %s\n", iface.HardwareAddr))
		result.WriteString(fmt.Sprintf("    MTU:   %d\n", iface.MTU))
		result.WriteString(fmt.Sprintf("    Flags: %s\n", flags))

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				addrStr := addr.String()
				// Classify IPv4 vs IPv6
				if strings.Contains(addrStr, ":") {
					result.WriteString(fmt.Sprintf("    IPv6:  %s\n", addrStr))
				} else {
					result.WriteString(fmt.Sprintf("    IPv4:  %s\n", addrStr))

					// Calculate network info for IPv4
					ip, ipNet, err := net.ParseCIDR(addrStr)
					if err == nil {
						result.WriteString(fmt.Sprintf("    Net:   %s\n", ipNet.String()))
						// Broadcast
						if ip4 := ip.To4(); ip4 != nil {
							broadcast := make(net.IP, 4)
							for i := range ip4 {
								broadcast[i] = ip4[i] | ^ipNet.Mask[i]
							}
							result.WriteString(fmt.Sprintf("    Bcast: %s\n", broadcast.String()))
						}
					}
				}
			}
		}
		result.WriteString("\n")
	}

	// Summary of routable IPs
	result.WriteString(strings.Repeat("─", 60) + "\n")
	result.WriteString("[*] Routable IPs:\n")
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			addrStr := addr.String()
			if !strings.Contains(addrStr, ":") { // IPv4 only
				ip, _, _ := net.ParseCIDR(addrStr)
				if ip != nil && !ip.IsLoopback() {
					result.WriteString(fmt.Sprintf("  %s → %s\n", iface.Name, addrStr))
				}
			}
		}
	}

	return []byte(result.String()), nil
}

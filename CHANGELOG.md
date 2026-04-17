# Phantom C2 — Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Web UI help command

- `help` / `?` in the Web UI terminal now returns the same agent command
  reference the CLI already shows (`cmdAgentHelp` in `internal/cli/shell.go`).
  Previously, typing `help` in the browser terminal fell through to the default
  branch and was sent to the target as a shell command.
- Server-side: `/api/cmd` intercepts `help` / `?` before task dispatch and
  returns `{inline: true, output: <reference>}` built by `buildAgentHelpText`
  in `internal/webui/webui.go`. The output is OS-aware (Mobile sections for
  Android/iOS; Execution, Lateral, Evasion, Active Directory for Windows/Linux).
- Client-side: the terminal input recognizes `help` and `?`, and inline
  responses are rendered directly without the task-poll loop.

## [1.0.2] — 2026-03-28

### 🔒 Web UI Auth, Payload Generator, Multi-Operator

**Web UI Authentication**
- Login page required for all dashboard access
- Default credentials: admin / phantom
- Session cookies with 24-hour expiry
- All API endpoints protected by auth middleware
- Dark themed login page matching dashboard

**Payload Generator (Web UI)**
- Generate any payload type from the browser
- 15 payload types: EXE, ELF, ASPX, PHP, JSP, PowerShell, Bash, Python, HTA, VBA, Android, iOS, Fake Apps
- Configure listener URL, sleep, jitter from the form
- Auto-download to browser after generation
- Download button for re-download
- Mobile app template selector (30+ templates)

**Multi-Operator Support**
- Multiple pentesters login simultaneously
- /api/operators shows who's online
- Agent notes track which operator added them

**Agent Notes**
- Add notes per agent (creds found, target info, pivot paths)
- GET/POST /api/notes?agent=<name>
- Timestamped with author name

**Task Output Search**
- Search across ALL command output from all agents
- GET /api/search?q=<query>
- Find passwords, hashes, or specific strings

**File Browser / Screenshot / Process List**
- Request directory listings, screenshots, process lists from Web UI
- Results appear in agent task history on next check-in

**Redirector Support**
- Generate configs for: Nginx, Apache, Cloudflare Worker, Caddy, socat, iptables
- Host header validation in HTTP profiles
- Redirector setup guide with OPSEC checklist

---

## [1.0.1] — 2026-03-28

### 🎨 Web UI Redesign + Stability Fixes

**Web UI — Complete Redesign**
- Mythic/Cobalt Strike-inspired dark theme with purple accent glow
- Beacon Activity line chart (real-time agent tracking over time)
- OS Distribution donut chart (Windows/Linux/Android/iOS)
- Session Health progress bars (Active/Dormant/Dead ratios)
- Network Topology graph (C2 server → agent connections with status colors)
- Agent cards with hover effects (click to interact)
- Interactive terminal with quick-action buttons
- Icon sidebar with agent badge counts
- Google Inter + JetBrains Mono fonts
- Auto-refresh every 4 seconds

**Authentication**
- Operator login with masked password input (stty -echo)
- First-run credential setup
- Password hashed with SHA-256 + salt
- All input reads from /dev/tty (fixes WSL terminal corruption)

**Stability Fixes**
- Fixed CLI not starting after password prompt on WSL
- Fixed "Both" mode (CLI + Web UI) startup timing
- All terminal input uses /dev/tty for reliability
- Basic mode fallback when readline fails

**Mobile**
- 30+ fake app templates with C2 callback
- Mobile evasion suite (anti-emulator, anti-Frida, anti-AV, anti-debug)
- /api/v1/mobile/checkin endpoint for Android/iOS agents
- Credential capture endpoint (/api/v1/creds)

**Diagnostics**
- Built-in troubleshooting: --doctor flag or 'doctor' command
- Checks 25+ items: config, keys, ports, network, tools, directories
- TROUBLESHOOTING.md with 10 common issues and fixes
- Versioning system: VERSION file, CHANGELOG.md, --version flag, git tags

---

## [1.0.0] — 2026-03-28

### 🎉 Initial Release

**Core Framework**
- CLI-first interface with tab completion, command history, and arrow keys
- Web UI dashboard (browser-based, runs alongside CLI)
- Dual mode: operators choose CLI, Web UI, or both on startup
- Operator authentication (first-run setup + login)
- Session recording to logs/ directory
- Engagement reporting (Markdown + CSV)
- SQLite database for persistent storage
- Docker deployment (Dockerfile + docker-compose.yml)

**Communications**
- HTTP/HTTPS listeners with malleable profiles
- DNS C2 listener (TXT record-based)
- SMB named pipe pivoting (Windows) / Unix socket (Linux)
- 3 built-in profiles: Default, Microsoft 365, Cloudflare Workers
- RSA-2048 key exchange + AES-256-GCM session encryption
- Auto key rotation every 100 check-ins
- JSON wire format disguised as API traffic

**Agent Capabilities (35+ commands)**
- Shell execution (cmd.exe / /bin/sh)
- File upload/download
- Screenshot capture
- Process listing
- System information
- Persistence (5 methods: registry, schtask, cron, systemd, bashrc)
- Token manipulation (steal, make, revert, impersonate)
- Keylogger
- SOCKS5 proxy + port forwarding
- Credential harvesting (browser, WiFi, clipboard, SSH, vault, RDP)

**Evasion & Stealth**
- AMSI bypass (patches AmsiScanBuffer)
- ETW bypass (patches EtwEventWrite)
- ntdll unhooking (loads clean .text from disk)
- Process hollowing (CreateProcess suspended + QueueUserAPC)
- Sandbox detection (uptime, CPU, hostname, env vars)
- Sleep obfuscation framework
- Linux: process name hiding, anti-debug

**In-Memory Execution**
- Beacon Object File (BOF) loader — in-memory COFF parser (Windows)
- memfd_create execution (Linux)
- Shellcode execution (VirtualAlloc/mmap)
- Remote process injection (CreateRemoteThread)

**Active Directory (22 commands)**
- Enumeration: domain, users, groups, computers, shares, SPNs, GPO, trusts, admins, AS-REP, delegation, LAPS
- Attacks: Kerberoast, AS-REP Roast, DCSync
- Credential access: SAM dump, LSA secrets, Kerberos tickets
- Lateral movement: PsExec, WMI, WinRM, Pass-the-Hash

**Payload Generation (16+ types)**
- Agent binaries: Windows EXE, Linux ELF (+ garble obfuscation)
- Web shells: ASPX, PHP, JSP (token-protected with 404 decoy)
- Stagers: PowerShell, Bash, Python
- Phishing: HTA, VBA macro
- Mobile: Android (APK builder + stagers), iOS (MDM profile + Apple ID phishing)
- App builder: 30+ fake app templates with C2 callback + evasion

**Mobile App Builder**
- 30+ templates across 7 categories (security, finance, social, corporate, etc.)
- Complete Android Studio project generation
- Background C2 service with boot persistence
- Mobile evasion: anti-emulator, anti-debug, anti-Frida, anti-AV, sandbox timing
- /api/v1/mobile/checkin endpoint for mobile callbacks
- Credential capture endpoint (/api/v1/creds)

**Webhook Notifications**
- Slack and Discord integration
- Auto-notify on agent registration, death, listener events

---

## Planned — v1.1.0

- TCP raw socket listener
- ICMP tunneling
- Multi-operator support
- Plugin/module system
- Agent screenshot via Web UI preview
- Interactive file browser
- Improved mobile APK signing automation

## Planned — v1.2.0

- Cobalt Strike aggressor script compatibility
- Full PE loader (in-memory)
- Process migration
- Network scanning from agent
- Automated lateral movement

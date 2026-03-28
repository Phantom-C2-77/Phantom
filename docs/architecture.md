# Phantom C2 - Architecture

## Overview

Phantom is a post-exploitation Command & Control framework designed for authorized red team engagements. It follows a server-agent architecture with encrypted communications over HTTP/HTTPS.

## Components

### Server
- **TUI**: Bubbletea-based terminal interface with 6 panels (Dashboard, Agents, Listeners, Tasks, Builder, Logs)
- **Listener Manager**: Manages HTTP/HTTPS listeners with malleable communication profiles
- **Agent Manager**: Tracks connected agents, status updates, session keys
- **Task Dispatcher**: Routes tasks to per-agent queues, processes results
- **Database**: SQLite for persistent storage of agents, tasks, results, and loot

### Agent (Implant)
- Cross-platform (Windows/Linux) Go binary
- Configurable at compile time via `-ldflags`
- Communicates over HTTP/HTTPS with AES-256-GCM encryption
- Supports: shell, file transfer, screenshots, process listing, persistence, sysinfo

## Communication Protocol

### Key Exchange
1. Agent generates random AES-256 session key
2. Agent encrypts session key + registration data with server's RSA-2048 public key
3. Server decrypts, stores session key in memory, responds with agent ID (AES-encrypted)

### Check-in Loop
1. Agent sleeps with configurable jitter
2. Agent sends AES-encrypted check-in (with any pending task results)
3. Server responds with AES-encrypted queued tasks
4. Agent executes tasks, collects results for next check-in

### Wire Format
- Inner payload: msgpack-serialized structs
- Encryption: AES-256-GCM with random nonce per message
- Outer format: Base64-encoded ciphertext in JSON wrapper
- HTTP disguise: Malleable profiles control URIs, headers, content-type

## Security Design

- Session keys stored in memory only (never on disk)
- RSA public key embedded in agent at compile time
- Agent-server mutual identification via key ID (SHA-256 of session key)
- Decoy responses for non-agent traffic
- User-Agent filtering per communication profile

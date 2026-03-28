package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ReadLine reads a line of visible text from /dev/tty.
func ReadLine() string {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		var s string
		fmt.Scanln(&s)
		return strings.TrimSpace(s)
	}
	defer tty.Close()

	reader := bufio.NewReader(tty)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

// ReadPassword reads a password without showing it on screen.
// Uses stty -echo to hide input, reads from /dev/tty for reliability.
func ReadPassword(prompt string) string {
	fmt.Print(prompt)

	// Open /dev/tty for reading (fresh fd, won't corrupt os.Stdin)
	tty, err := os.Open("/dev/tty")
	if err != nil {
		// Fallback — just read plain text from stdin
		var pass string
		fmt.Scanln(&pass)
		return strings.TrimSpace(pass)
	}
	defer tty.Close()

	// Disable terminal echo via stty
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()

	// Read password from /dev/tty
	reader := bufio.NewReader(tty)
	password, _ := reader.ReadString('\n')

	// Re-enable echo
	exec.Command("stty", "-F", "/dev/tty", "echo").Run()

	fmt.Println() // New line after hidden input
	return strings.TrimSpace(password)
}

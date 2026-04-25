package cli

import (
	"fmt"
	"runtime"
	"time"
)

const banner = `
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
`

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"

	// 256-color accents — richer violet + cyan matching Web UI palette
	colorViolet     = "\033[38;5;99m"   // #7c3aed-ish
	colorVioletBold = "\033[1;38;5;99m"
	colorCyanBright = "\033[38;5;51m"   // bright cyan
	colorCyanDim    = "\033[38;5;73m"   // muted cyan
	colorGreenBright= "\033[38;5;84m"   // bright green for active pulse
	colorRedBright  = "\033[38;5;203m"  // vivid red for dead
	colorOrange     = "\033[38;5;214m"  // amber for idle/dormant
	colorGrayDim    = "\033[38;5;240m"  // dark gray for secondary info

	colorBgRed   = "\033[41m"
	colorBgGreen = "\033[42m"

	// Exported for use in cmd/server
	ColorReset  = colorReset
	ColorPurple = colorPurple
	ColorCyan   = colorCyan
	ColorBold   = colorBold
	ColorDim    = colorDim
)

// PrintBanner displays the startup banner.
func PrintBanner(version string) {
	// Banner in gradient purple→cyan
	fmt.Printf("%s%s%s%s\n", colorBold, colorPurple, banner, colorReset)

	// Info box
	fmt.Printf("  %s╔══════════════════════════════════════════════════════════════╗%s\n", colorDim, colorReset)
	fmt.Printf("  %s║%s  %s%sC O M M A N D   &   C O N T R O L%s                          %s║%s\n", colorDim, colorReset, colorBold, colorCyan, colorReset, colorDim, colorReset)
	fmt.Printf("  %s║%s  %sRed Team Operations Framework%s                                %s║%s\n", colorDim, colorReset, colorDim, colorReset, colorDim, colorReset)
	fmt.Printf("  %s╠══════════════════════════════════════════════════════════════╣%s\n", colorDim, colorReset)
	fmt.Printf("  %s║%s  %sVersion%s  : %s%-15s%s  %sOS%s   : %s%-15s%s          %s║%s\n",
		colorDim, colorReset, colorDim, colorReset, colorCyan, version, colorReset,
		colorDim, colorReset, colorCyan, runtime.GOOS+"/"+runtime.GOARCH, colorReset,
		colorDim, colorReset)
	fmt.Printf("  %s║%s  %sDate%s     : %s%-15s%s  %sGo%s   : %s%-15s%s          %s║%s\n",
		colorDim, colorReset, colorDim, colorReset, colorCyan, time.Now().Format("2006-01-02"), colorReset,
		colorDim, colorReset, colorCyan, runtime.Version(), colorReset,
		colorDim, colorReset)
	fmt.Printf("  %s╠══════════════════════════════════════════════════════════════╣%s\n", colorDim, colorReset)
	fmt.Printf("  %s║%s  %s⚡ Agents%s : Windows • Linux • macOS • Android • iOS        %s║%s\n", colorDim, colorReset, colorYellow, colorReset, colorDim, colorReset)
	fmt.Printf("  %s║%s  %s🌐 Deliver%s: Phishing • APK • MSI • HTA • Macro • QR Code   %s║%s\n", colorDim, colorReset, colorYellow, colorReset, colorDim, colorReset)
	fmt.Printf("  %s║%s  %s🔒 Comms%s  : AES-256 + RSA envelope • HTTP/S • DNS • SMB     %s║%s\n", colorDim, colorReset, colorYellow, colorReset, colorDim, colorReset)
	fmt.Printf("  %s╚══════════════════════════════════════════════════════════════╝%s\n", colorDim, colorReset)
	fmt.Println()
}

// FormatPrompt builds the CLI prompt string.
func FormatPrompt(agentName string) string {
	if agentName != "" {
		return fmt.Sprintf("%s%s⚡ phantom%s [%s%s%s%s] ▸ %s",
			colorBold, colorPurple, colorReset,
			colorBold, colorCyan, agentName, colorReset,
			colorReset)
	}
	return fmt.Sprintf("%s%s⚡ phantom%s ▸ %s", colorBold, colorPurple, colorReset, colorReset)
}

// Success prints a green [+] message.
func Success(format string, args ...interface{}) {
	fmt.Printf("  %s%s[+]%s ", colorBold, colorGreen, colorReset)
	fmt.Printf(format+"\n", args...)
}

// Info prints a blue [*] message.
func Info(format string, args ...interface{}) {
	fmt.Printf("  %s[*]%s ", colorCyan, colorReset)
	fmt.Printf(format+"\n", args...)
}

// Warn prints a yellow [!] message.
func Warn(format string, args ...interface{}) {
	fmt.Printf("  %s%s[!]%s ", colorBold, colorYellow, colorReset)
	fmt.Printf(format+"\n", args...)
}

// Error prints a red [-] message.
func Error(format string, args ...interface{}) {
	fmt.Printf("  %s%s[-]%s ", colorBold, colorRed, colorReset)
	fmt.Printf(format+"\n", args...)
}

// Event prints a purple [>] event message.
func Event(format string, args ...interface{}) {
	fmt.Printf("  %s%s[»]%s ", colorBold, colorPurple, colorReset)
	fmt.Printf(format+"\n", args...)
}

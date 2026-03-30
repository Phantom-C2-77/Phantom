package cli

import "fmt"

const banner = `
                      ___
                 ____/   \____
            ____/    _   _    \____
       ____/   _____/ \_/ \_____   \____
  ____/  _____/   PHANTOM C2   \_____  \____
 /______/____________________________\______\
        \___        ✦        ___/
            \_______•_______/
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
	fmt.Printf("%s%s%s%s", colorBold, colorPurple, banner, colorReset)
	fmt.Printf("  %s%s[::] Phantom C2 Framework — Red Team Operations%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("  %s[::] Version: %s%s\n", colorDim, version, colorReset)
	fmt.Println()
}

// Success prints a green [+] message.
func Success(format string, args ...interface{}) {
	fmt.Printf("  %s[+]%s ", colorGreen, colorReset)
	fmt.Printf(format+"\n", args...)
}

// Info prints a blue [*] message.
func Info(format string, args ...interface{}) {
	fmt.Printf("  %s[*]%s ", colorBlue, colorReset)
	fmt.Printf(format+"\n", args...)
}

// Warn prints a yellow [!] message.
func Warn(format string, args ...interface{}) {
	fmt.Printf("  %s[!]%s ", colorYellow, colorReset)
	fmt.Printf(format+"\n", args...)
}

// Error prints a red [-] message.
func Error(format string, args ...interface{}) {
	fmt.Printf("  %s[-]%s ", colorRed, colorReset)
	fmt.Printf(format+"\n", args...)
}

// Event prints a purple [>] event message.
func Event(format string, args ...interface{}) {
	fmt.Printf("  %s[>]%s ", colorPurple, colorReset)
	fmt.Printf(format+"\n", args...)
}

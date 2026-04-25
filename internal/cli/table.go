package cli

import (
	"fmt"
	"strconv"
	"strings"
)

// Table renders a styled ASCII table with colored headers, OS icons,
// status badges, and proper box-drawing characters.
type Table struct {
	Title   string
	Headers []string
	Rows    [][]string
}

// NewTable creates a new table with headers.
func NewTable(headers ...string) *Table {
	return &Table{Headers: headers}
}

// AddRow adds a row to the table.
func (t *Table) AddRow(cols ...string) {
	t.Rows = append(t.Rows, cols)
}

// Render prints the table to stdout with professional styling.
func (t *Table) Render() {
	if len(t.Headers) == 0 {
		return
	}

	// Calculate column widths using display width (emoji-aware)
	widths := make([]int, len(t.Headers))
	for i, h := range t.Headers {
		widths[i] = displayWidth(h)
	}
	for _, row := range t.Rows {
		for i, col := range row {
			if i < len(widths) {
				enhanced := enhanceValue(col, t.Headers[i])
				raw := stripAnsi(enhanced)
				dw := displayWidth(raw)
				if dw > widths[i] {
					widths[i] = dw
				}
			}
		}
	}

	// Add padding
	for i := range widths {
		widths[i] += 2
	}

	// Build separators
	sepParts := make([]string, len(widths))
	for i, w := range widths {
		sepParts[i] = strings.Repeat("═", w)
	}
	thinParts := make([]string, len(widths))
	for i, w := range widths {
		thinParts[i] = strings.Repeat("─", w)
	}

	topSep := "  " + colorGrayDim + "╔" + strings.Join(sepParts, "╦") + "╗" + colorReset
	midSep := "  " + colorGrayDim + "╠" + strings.Join(sepParts, "╬") + "╣" + colorReset
	divSep := "  " + colorGrayDim + "╟" + strings.Join(thinParts, "╫") + "╢" + colorReset
	botSep := "  " + colorGrayDim + "╚" + strings.Join(sepParts, "╩") + "╝" + colorReset

	// Title
	if t.Title != "" {
		fmt.Printf("\n  %s%s  %s%s\n", colorVioletBold, "▸", t.Title, colorReset)
	}

	// Top border
	fmt.Println(topSep)

	// Header row
	fmt.Print("  " + colorGrayDim + "║" + colorReset)
	for i, h := range t.Headers {
		padded := padCenter(h, widths[i])
		fmt.Printf("%s%s%s%s%s%s", colorBold, colorCyanBright, padded, colorReset, colorGrayDim, "║"+colorReset)
	}
	fmt.Println()

	// Header separator
	fmt.Println(midSep)

	// Data rows
	for idx, row := range t.Rows {
		// Subtle alternating row dim
		rowDim := ""
		rowReset := ""
		if idx%2 == 1 {
			rowDim = colorDim
			rowReset = colorReset
		}

		fmt.Print("  " + colorGrayDim + "║" + colorReset)
		for i := range t.Headers {
			val := ""
			if i < len(row) {
				val = row[i]
			}
			colored := rowDim + enhanceValue(val, t.Headers[i]) + rowReset
			rawEnhanced := stripAnsi(colored)
			dw := displayWidth(rawEnhanced)

			padding := widths[i] - dw
			if padding < 0 {
				padding = 0
			}
			leftPad := 1
			rightPad := padding - leftPad
			if rightPad < 0 {
				rightPad = 0
			}
			fmt.Printf("%s%s%s%s%s", strings.Repeat(" ", leftPad), colored, strings.Repeat(" ", rightPad), colorGrayDim, "║"+colorReset)
		}
		fmt.Println()

		// Thin divider between rows (except last)
		if idx < len(t.Rows)-1 {
			fmt.Println(divSep)
		}
	}

	// Bottom border
	fmt.Println(botSep)

	// Row count
	fmt.Printf("  %s%d row(s)%s\n\n", colorGrayDim, len(t.Rows), colorReset)
}

// padCenter centers a string within a given width (display-width aware).
func padCenter(s string, width int) string {
	dw := displayWidth(s)
	if dw >= width {
		return s
	}
	total := width - dw
	left := total / 2
	right := total - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}

// enhanceValue applies color and icons based on the value and column header.
func enhanceValue(val, header string) string {
	lower := strings.ToLower(strings.TrimSpace(val))
	headerLower := strings.ToLower(header)

	// Status column
	if headerLower == "status" || headerLower == "state" {
		switch lower {
		case "active", "running":
			return colorGreenBright + colorBold + "● " + colorReset + colorGreenBright + val + colorReset
		case "dormant", "idle":
			return colorOrange + "◑ " + val + colorReset
		case "dead", "stopped":
			return colorRedBright + "○ " + val + colorReset
		case "pending":
			return colorOrange + "⏳ " + val + colorReset
		case "sent":
			return colorCyanBright + "➤ " + val + colorReset
		case "complete":
			return colorGreenBright + "✓ " + val + colorReset
		case "error":
			return colorRedBright + "✗ " + val + colorReset
		}
		return colorGrayDim + val + colorReset
	}

	// OS column — icons + color
	if headerLower == "os" {
		switch {
		case strings.Contains(lower, "windows") || strings.Contains(lower, "win"):
			return "🪟 " + colorCyanBright + val + colorReset
		case strings.Contains(lower, "linux"):
			return "🐧 " + colorGreenBright + val + colorReset
		case strings.Contains(lower, "android"):
			return "📱 " + colorGreenBright + val + colorReset
		case strings.Contains(lower, "ios"):
			return "🍎 " + colorWhite + val + colorReset
		case strings.Contains(lower, "darwin"):
			return "🍎 " + colorWhite + "macOS" + colorReset
		case strings.Contains(lower, "macos"):
			return "🍎 " + colorWhite + val + colorReset
		}
		return colorGrayDim + val + colorReset
	}

	// Name column — violet bold
	if headerLower == "name" {
		return colorVioletBold + val + colorReset
	}

	// IP / Bind column — bright cyan monospace
	if headerLower == "ip" || headerLower == "bind" || headerLower == "address" {
		return colorCyanBright + val + colorReset
	}

	// Hostname — dim white
	if headerLower == "hostname" || headerLower == "host" {
		return colorWhite + val + colorReset
	}

	// User column — dim
	if headerLower == "user" || headerLower == "username" {
		return colorGrayDim + val + colorReset
	}

	// Sleep column — dim, secondary info
	if headerLower == "sleep" || headerLower == "interval" {
		return colorGrayDim + val + colorReset
	}

	// Last Seen — color by recency
	if headerLower == "last seen" || headerLower == "lastseen" || headerLower == "last_seen" {
		return colorizeAge(val)
	}

	// Type column — orange
	if headerLower == "type" {
		return colorOrange + val + colorReset
	}

	// ID column — dim
	if headerLower == "id" {
		return colorGrayDim + val + colorReset
	}

	return val
}

// colorizeAge colors a "X ago" or duration string by recency.
func colorizeAge(val string) string {
	lower := strings.ToLower(strings.TrimSpace(val))

	// Parse "Xs ago", "Xm ago", "just now" etc.
	if lower == "just now" || lower == "0s ago" {
		return colorGreenBright + colorBold + val + colorReset
	}

	// Try to extract seconds
	secs := parseAgoSeconds(lower)
	switch {
	case secs < 0:
		return colorGrayDim + val + colorReset
	case secs <= 30:
		return colorGreenBright + val + colorReset
	case secs <= 120:
		return colorOrange + val + colorReset
	default:
		return colorRedBright + val + colorReset
	}
}

// parseAgoSeconds parses "Xs ago", "Xm ago", "Xh ago" → seconds. Returns -1 if unparseable.
func parseAgoSeconds(s string) int {
	s = strings.TrimSuffix(s, " ago")
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "s") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "s"))
		if err == nil {
			return n
		}
	}
	if strings.HasSuffix(s, "m") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "m"))
		if err == nil {
			return n * 60
		}
	}
	if strings.HasSuffix(s, "h") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "h"))
		if err == nil {
			return n * 3600
		}
	}
	return -1
}

// stripAnsi removes ANSI escape codes for width calculation.
func stripAnsi(s string) string {
	result := make([]byte, 0, len(s))
	inEscape := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') {
				inEscape = false
			}
			continue
		}
		result = append(result, s[i])
	}
	return string(result)
}

// displayWidth returns the number of terminal columns a string occupies.
func displayWidth(s string) int {
	width := 0
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r >= 0x1F000 ||
			(r >= 0x2600 && r <= 0x27BF) ||
			(r >= 0x2700 && r <= 0x27BF) ||
			(r >= 0xFE00 && r <= 0xFE0F) ||
			(r >= 0x1F300 && r <= 0x1FAFF) ||
			r == 0x25CF || r == 0x25D0 || r == 0x25CB || r == 0x25D1 ||
			r == 0x26A1 ||
			r == 0x2713 || r == 0x2717 ||
			r == 0x23F3 ||
			r == 0x27A4 ||
			r == 0x1F4E4 {
			width += 2
		} else {
			width += 1
		}
	}
	return width
}


package cli

import (
	"fmt"
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

	// Calculate column widths (based on raw text, not ANSI codes)
	widths := make([]int, len(t.Headers))
	for i, h := range t.Headers {
		widths[i] = len(h)
	}
	for _, row := range t.Rows {
		for i, col := range row {
			if i < len(widths) {
				raw := stripAnsi(col)
				if len(raw) > widths[i] {
					widths[i] = len(raw)
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

	topSep := "  " + colorDim + "╔" + strings.Join(sepParts, "╦") + "╗" + colorReset
	midSep := "  " + colorDim + "╠" + strings.Join(sepParts, "╬") + "╣" + colorReset
	divSep := "  " + colorDim + "╟" + strings.Join(thinParts, "╫") + "╢" + colorReset
	botSep := "  " + colorDim + "╚" + strings.Join(sepParts, "╩") + "╝" + colorReset

	// Title
	if t.Title != "" {
		totalWidth := 0
		for _, w := range widths {
			totalWidth += w
		}
		totalWidth += len(widths) - 1 // separators
		fmt.Printf("\n  %s%s %s %s\n", colorBold, colorPurple, t.Title, colorReset)
	}

	// Top border
	fmt.Println(topSep)

	// Header row
	fmt.Print("  " + colorDim + "║" + colorReset)
	for i, h := range t.Headers {
		padded := padCenter(h, widths[i])
		fmt.Printf("%s%s%s%s%s%s", colorBold, colorCyan, padded, colorReset, colorDim, "║"+colorReset)
	}
	fmt.Println()

	// Header separator
	fmt.Println(midSep)

	// Data rows
	for idx, row := range t.Rows {
		fmt.Print("  " + colorDim + "║" + colorReset)
		for i := range t.Headers {
			val := ""
			if i < len(row) {
				val = row[i]
			}
			// Apply color + icons
			colored := enhanceValue(val, t.Headers[i])
			raw := stripAnsi(val)

			// Pad based on raw value length
			padding := widths[i] - len(raw)
			if padding < 0 {
				padding = 0
				val = val[:widths[i]]
				colored = enhanceValue(val, t.Headers[i])
				raw = val
			}
			leftPad := 1
			rightPad := padding - leftPad
			if rightPad < 0 {
				rightPad = 0
			}
			fmt.Printf("%s%s%s%s%s", strings.Repeat(" ", leftPad), colored, strings.Repeat(" ", rightPad), colorDim, "║"+colorReset)
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
	fmt.Printf("  %s%d row(s)%s\n", colorDim, len(t.Rows), colorReset)
}

// padCenter centers a string within a given width.
func padCenter(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	total := width - len(s)
	left := total / 2
	right := total - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}

// enhanceValue applies color and icons based on the value and column header.
func enhanceValue(val, header string) string {
	lower := strings.ToLower(strings.TrimSpace(val))
	headerLower := strings.ToLower(header)

	// Status column — colored dots
	if headerLower == "status" {
		switch lower {
		case "active", "running":
			return colorGreen + colorBold + "● " + val + colorReset
		case "dormant":
			return colorYellow + "◐ " + val + colorReset
		case "dead", "stopped":
			return colorRed + "○ " + val + colorReset
		}
	}

	// OS column — icons
	if headerLower == "os" {
		switch {
		case strings.Contains(lower, "windows") || strings.Contains(lower, "win"):
			return "🪟 " + colorBlue + val + colorReset
		case strings.Contains(lower, "linux"):
			return "🐧 " + colorGreen + val + colorReset
		case strings.Contains(lower, "android"):
			return "📱 " + colorGreen + val + colorReset
		case strings.Contains(lower, "ios") || strings.Contains(lower, "darwin"):
			return "🍎 " + colorWhite + val + colorReset
		case strings.Contains(lower, "macos"):
			return "🍎 " + colorWhite + val + colorReset
		}
	}

	// Task status
	if headerLower == "status" || headerLower == "state" {
		switch lower {
		case "pending":
			return colorYellow + "⏳ " + val + colorReset
		case "sent":
			return colorBlue + "📤 " + val + colorReset
		case "complete":
			return colorGreen + "✓ " + val + colorReset
		case "error":
			return colorRed + "✗ " + val + colorReset
		}
	}

	// Name column — highlight
	if headerLower == "name" {
		return colorBold + colorPurple + val + colorReset
	}

	// IP column — monospace feel
	if headerLower == "ip" || headerLower == "bind" {
		return colorCyan + val + colorReset
	}

	// Type column
	if headerLower == "type" {
		return colorYellow + val + colorReset
	}

	// Default colorize
	switch lower {
	case "active", "running":
		return colorGreen + val + colorReset
	case "dormant", "pending", "sent":
		return colorYellow + val + colorReset
	case "dead", "error", "stopped":
		return colorRed + val + colorReset
	case "complete":
		return colorCyan + val + colorReset
	}

	return val
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

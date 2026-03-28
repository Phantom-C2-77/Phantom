package protocol

// Protocol version
const ProtocolVersion uint8 = 1

// Message types
const (
	MsgRegisterRequest  uint8 = 0x01
	MsgRegisterResponse uint8 = 0x02
	MsgCheckIn          uint8 = 0x03
	MsgCheckInResponse  uint8 = 0x04
	MsgTaskResult       uint8 = 0x05
)

// Task types
const (
	TaskShell       uint8 = 1
	TaskUpload      uint8 = 2
	TaskDownload    uint8 = 3
	TaskScreenshot  uint8 = 4
	TaskProcessList uint8 = 5
	TaskPersist     uint8 = 6
	TaskSysinfo     uint8 = 7
	TaskSleep       uint8 = 8
	TaskKill        uint8 = 9
	TaskCd          uint8 = 10
	TaskAD          uint8 = 11  // Active Directory commands
	TaskBOF         uint8 = 12  // Beacon Object File execution
	TaskShellcode   uint8 = 13  // In-memory shellcode execution
	TaskInject      uint8 = 14  // Remote process injection
	TaskHollow      uint8 = 15  // Process hollowing
	TaskEvasion     uint8 = 16  // Run/re-run evasion techniques
)

// Task status
const (
	StatusPending  uint8 = 0
	StatusSent     uint8 = 1
	StatusComplete uint8 = 2
	StatusError    uint8 = 3
)

// Agent status
const (
	AgentActive  = "active"
	AgentDormant = "dormant"
	AgentDead    = "dead"
)

// TaskTypeName returns a human-readable name for a task type.
func TaskTypeName(t uint8) string {
	switch t {
	case TaskShell:
		return "shell"
	case TaskUpload:
		return "upload"
	case TaskDownload:
		return "download"
	case TaskScreenshot:
		return "screenshot"
	case TaskProcessList:
		return "ps"
	case TaskPersist:
		return "persist"
	case TaskSysinfo:
		return "sysinfo"
	case TaskSleep:
		return "sleep"
	case TaskKill:
		return "kill"
	case TaskCd:
		return "cd"
	case TaskAD:
		return "ad"
	case TaskBOF:
		return "bof"
	case TaskShellcode:
		return "shellcode"
	case TaskInject:
		return "inject"
	case TaskHollow:
		return "hollow"
	case TaskEvasion:
		return "evasion"
	default:
		return "unknown"
	}
}

// StatusName returns a human-readable name for a task status.
func StatusName(s uint8) string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusSent:
		return "sent"
	case StatusComplete:
		return "complete"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

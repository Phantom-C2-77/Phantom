package implant

// These variables are injected at compile time via -ldflags.
// Example: go build -ldflags "-X 'github.com/phantom-c2/phantom/internal/implant.ListenerURL=https://c2.example.com:443'"
var (
	Version       = "dev"
	ListenerURL   = "https://127.0.0.1:443"
	SleepSeconds  = "10"
	JitterPercent = "20"
	KillDate      = ""          // Optional: YYYY-MM-DD format, agent self-terminates after this date
	ServerPubKey  = ""          // Base64-encoded RSA public key (embedded at compile time)
	RunAsService  = ""          // Set to "true" to run as Windows service
)

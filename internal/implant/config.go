package implant

// These variables are injected at compile time via -ldflags.
// Example: go build -ldflags "-X 'github.com/phantom-c2/phantom/internal/implant.ListenerURL=https://c2.example.com:443'"
// ListenerURL is a comma-separated list of C2 URLs for failover rotation.
// Example with failover: -X '.../ListenerURL=https://primary:443,https://backup:443'
var (
	Version       = "dev"
	ListenerURL   = "https://127.0.0.1:443"
	SleepSeconds  = "10"
	JitterPercent = "20"
	KillDate      = ""          // Optional: YYYY-MM-DD format, agent self-terminates after this date
	ServerPubKey  = ""          // Base64-encoded RSA public key (embedded at compile time)
	RunAsService  = ""          // Set to "true" to run as Windows service
	FrontDomain   = ""          // CDN domain for SNI-based domain fronting (e.g., "cdn.microsoft.com")
	HostHeader    = ""          // Override HTTP Host header for domain fronting (e.g., "c2.workers.dev")
)

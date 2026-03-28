package listener

import (
	"math/rand"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// HTTPProfile defines a full malleable HTTP profile for C2 traffic shaping.
// Similar to Cobalt Strike's malleable C2 profiles — controls how traffic
// looks on the wire to blend in with legitimate traffic.
type HTTPProfile struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`

	// ── Client (Agent → Server) ──
	Client ClientProfile          `yaml:"client"`

	// ── Server (Server → Agent) ──
	Server ServerProfile          `yaml:"server"`

	// ── Host Validation ──
	// Only respond to C2 traffic if the Host header matches one of these.
	// All other requests get the decoy response. Essential for redirector setups.
	AllowedHosts []string         `yaml:"allowed_hosts"`

	// ── Decoy ──
	Decoy DecoyConfig             `yaml:"decoy"`
}

// ClientProfile controls how the agent sends requests.
type ClientProfile struct {
	UserAgent   string            `yaml:"user_agent"`
	Headers     map[string]string `yaml:"headers"`

	// URIs — the agent picks one randomly per request for variation
	RegisterURIs []string         `yaml:"register_uris"`
	CheckInURIs  []string         `yaml:"checkin_uris"`

	// HTTP method (GET or POST)
	Method      string            `yaml:"method"`

	// How to encode the C2 data in the request
	// Options: "body" (POST body), "cookie" (in cookie header),
	//          "header" (custom header), "uri" (as URI parameter)
	DataTransform string          `yaml:"data_transform"`

	// Parameter name when using "uri" or "cookie" transform
	ParamName   string            `yaml:"param_name"`
}

// ServerProfile controls how the server sends responses.
type ServerProfile struct {
	Headers     map[string]string `yaml:"headers"`
	ContentType string            `yaml:"content_type"`
	StatusCode  int               `yaml:"status_code"`

	// How to encode C2 data in the response
	// Options: "body", "header", "cookie"
	DataTransform string          `yaml:"data_transform"`

	// Prepend/append to make responses look like real content
	Prepend     string            `yaml:"prepend"`
	Append      string            `yaml:"append"`
}

// DecoyConfig controls what non-C2 visitors see.
type DecoyConfig struct {
	StatusCode  int               `yaml:"status_code"`
	ContentType string            `yaml:"content_type"`
	Body        string            `yaml:"body"`
	Headers     map[string]string `yaml:"headers"`

	// Serve a file instead of inline body
	ServeFile   string            `yaml:"serve_file"`

	// Redirect non-C2 traffic to a real website
	RedirectURL string            `yaml:"redirect_url"`
}

// LoadHTTPProfile reads a full HTTP profile from YAML.
func LoadHTTPProfile(path string) (*HTTPProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var wrapper struct {
		Profile HTTPProfile `yaml:"profile"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, err
	}

	p := &wrapper.Profile
	p.setDefaults()
	return p, nil
}

// setDefaults fills in missing values.
func (p *HTTPProfile) setDefaults() {
	if p.Name == "" {
		p.Name = "default"
	}
	if len(p.Client.RegisterURIs) == 0 {
		p.Client.RegisterURIs = []string{"/api/v1/auth"}
	}
	if len(p.Client.CheckInURIs) == 0 {
		p.Client.CheckInURIs = []string{"/api/v1/status"}
	}
	if p.Client.UserAgent == "" {
		p.Client.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}
	if p.Client.Method == "" {
		p.Client.Method = "POST"
	}
	if p.Client.DataTransform == "" {
		p.Client.DataTransform = "body"
	}
	if p.Server.ContentType == "" {
		p.Server.ContentType = "application/json"
	}
	if p.Server.StatusCode == 0 {
		p.Server.StatusCode = 200
	}
	if p.Server.DataTransform == "" {
		p.Server.DataTransform = "body"
	}
	if p.Decoy.StatusCode == 0 {
		p.Decoy.StatusCode = 200
	}
	if p.Decoy.ContentType == "" {
		p.Decoy.ContentType = "text/html"
	}
}

// RandomRegisterURI returns a random registration URI for variation.
func (p *HTTPProfile) RandomRegisterURI() string {
	if len(p.Client.RegisterURIs) == 0 {
		return "/api/v1/auth"
	}
	return p.Client.RegisterURIs[rand.Intn(len(p.Client.RegisterURIs))]
}

// RandomCheckInURI returns a random check-in URI.
func (p *HTTPProfile) RandomCheckInURI() string {
	if len(p.Client.CheckInURIs) == 0 {
		return "/api/v1/status"
	}
	return p.Client.CheckInURIs[rand.Intn(len(p.Client.CheckInURIs))]
}

// IsAllowedHost checks if the Host header is in the allowed list.
// If no allowed hosts are configured, all hosts are allowed.
func (p *HTTPProfile) IsAllowedHost(host string) bool {
	if len(p.AllowedHosts) == 0 {
		return true // No restriction
	}
	// Strip port from host
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	host = strings.ToLower(host)

	for _, allowed := range p.AllowedHosts {
		if strings.ToLower(allowed) == host {
			return true
		}
		// Wildcard support: *.example.com
		if strings.HasPrefix(allowed, "*.") {
			suffix := strings.ToLower(allowed[1:]) // .example.com
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

// ResolveServerHeaders returns response headers with template values filled.
func (p *HTTPProfile) ResolveServerHeaders() map[string]string {
	resolved := make(map[string]string)
	for k, v := range p.Server.Headers {
		v = strings.ReplaceAll(v, "{{timestamp}}", time.Now().Format(time.RFC1123))
		v = strings.ReplaceAll(v, "{{date}}", time.Now().Format("2006-01-02"))
		resolved[k] = v
	}
	return resolved
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

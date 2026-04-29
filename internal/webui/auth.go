package webui

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WebAuth handles authentication for the Web UI.
type WebAuth struct {
	mu       sync.RWMutex
	users    map[string]*WebUser // username -> user
	sessions map[string]*WebSession // token -> session
}

type WebUser struct {
	Username string `json:"username"`
	PassHash string `json:"pass_hash"`
	Salt     string `json:"salt"`
	Role     string `json:"role"` // admin, operator, viewer
}

type WebSession struct {
	Token     string
	Username  string
	Role      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewWebAuth() *WebAuth {
	wa := &WebAuth{
		users:    make(map[string]*WebUser),
		sessions: make(map[string]*WebSession),
	}
	// Default admin user — operator should change this
	wa.CreateUser("admin", "phantom", "admin")
	return wa
}

func (wa *WebAuth) CreateUser(username, password, role string) {
	salt := randomHex(16)
	hash := hashPass(password, salt)
	wa.mu.Lock()
	wa.users[username] = &WebUser{Username: username, PassHash: hash, Salt: salt, Role: role}
	wa.mu.Unlock()
}

func (wa *WebAuth) Authenticate(username, password string) (string, error) {
	wa.mu.RLock()
	user, ok := wa.users[username]
	wa.mu.RUnlock()

	if !ok || hashPass(password, user.Salt) != user.PassHash {
		return "", fmt.Errorf("invalid credentials")
	}

	token := randomHex(32)
	wa.mu.Lock()
	wa.sessions[token] = &WebSession{
		Token: token, Username: username, Role: user.Role,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	wa.mu.Unlock()

	return token, nil
}

func (wa *WebAuth) ValidateRequest(r *http.Request) *WebSession {
	// Check cookie
	c, err := r.Cookie("phantom_session")
	if err != nil || c.Value == "" {
		return nil
	}

	wa.mu.RLock()
	session, ok := wa.sessions[c.Value]
	wa.mu.RUnlock()

	if !ok || time.Now().After(session.ExpiresAt) {
		return nil
	}
	return session
}

// AuthMiddleware wraps handlers requiring authentication.
// Supports both cookie-based sessions and API key authentication.
func (wa *WebAuth) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check session cookie first
		session := wa.ValidateRequest(r)
		if session != nil {
			next(w, r)
			return
		}
		// Check API key (for scripting/automation)
		if ValidateAPIKey(r) {
			next(w, r)
			return
		}
		// Login pages don't need auth
		if r.URL.Path == "/login" || r.URL.Path == "/api/login" {
			next(w, r)
			return
		}
		// API endpoints: return JSON 401 so fetch() gets parseable JSON, not HTML
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"session expired — please log in again"}`)
			return
		}
		http.Redirect(w, r, "/login", 302)
	}
}

func (wa *WebAuth) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, loginPageHTML)
		return
	}

	// POST — API login
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" {
		json.NewDecoder(r.Body).Decode(&req)
	} else {
		req.Username = r.FormValue("username")
		req.Password = r.FormValue("password")
	}

	token, err := wa.Authenticate(req.Username, req.Password)
	if err != nil {
		if contentType == "application/json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
		} else {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, loginPageHTMLError)
		}
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "phantom_session", Value: token, Path: "/",
		MaxAge: 86400, HttpOnly: true,
	})

	if contentType == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "token": token})
	} else {
		http.Redirect(w, r, "/", 302)
	}
}

func (wa *WebAuth) HandleLogout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("phantom_session")
	if c != nil {
		wa.mu.Lock()
		delete(wa.sessions, c.Value)
		wa.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "phantom_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", 302)
}

func (wa *WebAuth) GetOnlineOperators() []string {
	wa.mu.RLock()
	defer wa.mu.RUnlock()
	seen := map[string]bool{}
	var ops []string
	for _, s := range wa.sessions {
		if !time.Now().After(s.ExpiresAt) && !seen[s.Username] {
			ops = append(ops, s.Username)
			seen[s.Username] = true
		}
	}
	return ops
}

func hashPass(password, salt string) string {
	h := sha256.Sum256([]byte(password + salt))
	return hex.EncodeToString(h[:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

const loginPageHTML = `<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phantom C2 — Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e1a;color:#e8ecf4;font-family:'Segoe UI',system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-card{background:#111827;border:1px solid #1f2937;border-radius:16px;padding:40px;width:100%;max-width:380px;box-shadow:0 8px 40px rgba(0,0,0,0.5)}
.login-card h1{text-align:center;font-size:24px;color:#a78bfa;margin-bottom:6px}
.login-card p{text-align:center;color:#6b7280;font-size:13px;margin-bottom:24px}
.login-card .icon{text-align:center;font-size:48px;margin-bottom:16px}
.field{margin-bottom:14px}
.field label{display:block;font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.field input{width:100%;padding:11px 14px;background:#0a0e1a;border:1px solid #2a3050;border-radius:8px;color:#e8ecf4;font-size:14px;outline:none}
.field input:focus{border-color:#7c3aed}
.btn{width:100%;padding:12px;background:#7c3aed;color:white;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;margin-top:8px}
.btn:hover{background:#6d28d9}
.error{background:rgba(239,68,68,0.12);color:#ef4444;border:1px solid rgba(239,68,68,0.25);padding:10px;border-radius:8px;margin-bottom:14px;font-size:13px;text-align:center;display:none}
</style></head><body>
<div class="login-card">
<div class="icon"><svg viewBox="0 0 100 50" xmlns="http://www.w3.org/2000/svg" width="80"><defs><linearGradient id="b2g" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:#a78bfa"/><stop offset="100%" style="stop-color:#6d28d9"/></linearGradient></defs><path d="M50 8 L15 30 L2 28 L8 32 L15 35 L28 38 L42 42 L50 44 L58 42 L72 38 L85 35 L92 32 L98 28 L85 30 Z" fill="url(#b2g)"/><path d="M50 12 L35 28 L50 36 L65 28 Z" fill="rgba(10,14,26,0.4)"/><circle cx="50" cy="26" r="2" fill="#a78bfa" opacity="0.8"/></svg></div>
<h1>Phantom C2</h1>
<p>Sign in to access the dashboard</p>
<form method="POST" action="/login">
<div class="field"><label>Username</label><input type="text" name="username" autofocus required></div>
<div class="field"><label>Password</label><input type="password" name="password" required></div>
<button type="submit" class="btn">Sign In</button>
</form>
<p style="margin-top:16px;font-size:11px;color:#4b5563;text-align:center">Phantom C2 Framework</p>
</div></body></html>`

const loginPageHTMLError = `<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phantom C2 — Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e1a;color:#e8ecf4;font-family:'Segoe UI',system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-card{background:#111827;border:1px solid #1f2937;border-radius:16px;padding:40px;width:100%;max-width:380px;box-shadow:0 8px 40px rgba(0,0,0,0.5)}
.login-card h1{text-align:center;font-size:24px;color:#a78bfa;margin-bottom:6px}
.login-card p{text-align:center;color:#6b7280;font-size:13px;margin-bottom:24px}
.login-card .icon{text-align:center;font-size:48px;margin-bottom:16px}
.field{margin-bottom:14px}
.field label{display:block;font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.field input{width:100%;padding:11px 14px;background:#0a0e1a;border:1px solid #2a3050;border-radius:8px;color:#e8ecf4;font-size:14px;outline:none}
.field input:focus{border-color:#7c3aed}
.btn{width:100%;padding:12px;background:#7c3aed;color:white;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;margin-top:8px}
.btn:hover{background:#6d28d9}
.error{background:rgba(239,68,68,0.12);color:#ef4444;border:1px solid rgba(239,68,68,0.25);padding:10px;border-radius:8px;margin-bottom:14px;font-size:13px;text-align:center}
</style></head><body>
<div class="login-card">
<div class="icon"><svg viewBox="0 0 100 50" xmlns="http://www.w3.org/2000/svg" width="80"><defs><linearGradient id="b2g" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:#a78bfa"/><stop offset="100%" style="stop-color:#6d28d9"/></linearGradient></defs><path d="M50 8 L15 30 L2 28 L8 32 L15 35 L28 38 L42 42 L50 44 L58 42 L72 38 L85 35 L92 32 L98 28 L85 30 Z" fill="url(#b2g)"/><path d="M50 12 L35 28 L50 36 L65 28 Z" fill="rgba(10,14,26,0.4)"/><circle cx="50" cy="26" r="2" fill="#a78bfa" opacity="0.8"/></svg></div>
<h1>Phantom C2</h1>
<p>Sign in to access the dashboard</p>
<div class="error">Invalid username or password</div>
<form method="POST" action="/login">
<div class="field"><label>Username</label><input type="text" name="username" autofocus required></div>
<div class="field"><label>Password</label><input type="password" name="password" required></div>
<button type="submit" class="btn">Sign In</button>
</form>
</div></body></html>`

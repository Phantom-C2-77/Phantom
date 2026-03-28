//go:build !windows && !linux

package implant

import "fmt"

func InitEvasion() []string {
	return []string{"Evasion: not supported on this platform"}
}

func ProcessHollow(hostProcess string, payload []byte) error {
	return fmt.Errorf("process hollowing not supported on this platform")
}

func PatchAMSI() error  { return nil }
func PatchETW() error   { return nil }
func UnhookNtdll() error { return nil }

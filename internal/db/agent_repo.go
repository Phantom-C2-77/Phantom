package db

import (
	"database/sql"
	"time"
)

// Agent represents a connected agent record.
type Agent struct {
	ID          string
	Name        string
	ExternalIP  string
	InternalIP  string
	Hostname    string
	Username    string
	OS          string
	Arch        string
	PID         int
	ProcessName string
	Sleep       int
	Jitter      int
	FirstSeen   time.Time
	LastSeen    time.Time
	Status      string
	ListenerID  string
	Tags        string // comma-separated tag list
}

// InsertAgent adds a new agent record.
func (db *Database) InsertAgent(a *Agent) error {
	_, err := db.conn.Exec(`
		INSERT INTO agents (id, name, external_ip, internal_ip, hostname, username, os, arch, pid, process_name, sleep, jitter, first_seen, last_seen, status, listener_id, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Name, a.ExternalIP, a.InternalIP, a.Hostname, a.Username, a.OS, a.Arch,
		a.PID, a.ProcessName, a.Sleep, a.Jitter, a.FirstSeen, a.LastSeen, a.Status, a.ListenerID, a.Tags,
	)
	return err
}

// GetAgent retrieves an agent by ID.
func (db *Database) GetAgent(id string) (*Agent, error) {
	a := &Agent{}
	err := db.conn.QueryRow(`SELECT id, name, external_ip, internal_ip, hostname, username, os, arch, pid, process_name, sleep, jitter, first_seen, last_seen, status, listener_id, COALESCE(tags,'') FROM agents WHERE id = ?`, id).
		Scan(&a.ID, &a.Name, &a.ExternalIP, &a.InternalIP, &a.Hostname, &a.Username, &a.OS, &a.Arch,
			&a.PID, &a.ProcessName, &a.Sleep, &a.Jitter, &a.FirstSeen, &a.LastSeen, &a.Status, &a.ListenerID, &a.Tags)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// GetAgentByName retrieves an agent by name.
func (db *Database) GetAgentByName(name string) (*Agent, error) {
	a := &Agent{}
	err := db.conn.QueryRow(`SELECT id, name, external_ip, internal_ip, hostname, username, os, arch, pid, process_name, sleep, jitter, first_seen, last_seen, status, listener_id, COALESCE(tags,'') FROM agents WHERE name = ?`, name).
		Scan(&a.ID, &a.Name, &a.ExternalIP, &a.InternalIP, &a.Hostname, &a.Username, &a.OS, &a.Arch,
			&a.PID, &a.ProcessName, &a.Sleep, &a.Jitter, &a.FirstSeen, &a.LastSeen, &a.Status, &a.ListenerID, &a.Tags)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// ListAgents returns all agents.
func (db *Database) ListAgents() ([]*Agent, error) {
	rows, err := db.conn.Query(`SELECT id, name, external_ip, internal_ip, hostname, username, os, arch, pid, process_name, sleep, jitter, first_seen, last_seen, status, listener_id, COALESCE(tags,'') FROM agents ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []*Agent
	for rows.Next() {
		a := &Agent{}
		if err := rows.Scan(&a.ID, &a.Name, &a.ExternalIP, &a.InternalIP, &a.Hostname, &a.Username, &a.OS, &a.Arch,
			&a.PID, &a.ProcessName, &a.Sleep, &a.Jitter, &a.FirstSeen, &a.LastSeen, &a.Status, &a.ListenerID, &a.Tags); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// UpdateAgentLastSeen updates the last_seen timestamp and status.
func (db *Database) UpdateAgentLastSeen(id string, lastSeen time.Time, status string) error {
	_, err := db.conn.Exec(`UPDATE agents SET last_seen = ?, status = ? WHERE id = ?`, lastSeen, status, id)
	return err
}

// UpdateAgentSleep updates the sleep and jitter settings.
func (db *Database) UpdateAgentSleep(id string, sleep, jitter int) error {
	_, err := db.conn.Exec(`UPDATE agents SET sleep = ?, jitter = ? WHERE id = ?`, sleep, jitter, id)
	return err
}

// UpdateAgentName renames an agent.
func (db *Database) UpdateAgentName(id, name string) error {
	_, err := db.conn.Exec(`UPDATE agents SET name = ? WHERE id = ?`, name, id)
	return err
}

// UpdateAgentTags sets the tags for an agent (comma-separated string).
func (db *Database) UpdateAgentTags(id, tags string) error {
	_, err := db.conn.Exec(`UPDATE agents SET tags = ? WHERE id = ?`, tags, id)
	return err
}

// DeleteAgent removes an agent and all related records (tasks, results, loot).
func (db *Database) DeleteAgent(id string) error {
	db.conn.Exec(`DELETE FROM task_results WHERE agent_id = ?`, id)
	db.conn.Exec(`DELETE FROM loot WHERE agent_id = ?`, id)
	db.conn.Exec(`DELETE FROM tasks WHERE agent_id = ?`, id)
	_, err := db.conn.Exec(`DELETE FROM agents WHERE id = ?`, id)
	return err
}

// ──── Payload History ────

// InsertPayloadRecord persists a payload generation record.
func (db *Database) InsertPayloadRecord(id, ptype, filename, fpath, size, listener, createdAt string) error {
	_, err := db.conn.Exec(
		`INSERT OR REPLACE INTO payload_history (id, type, filename, filepath, size, listener, created_at) VALUES (?,?,?,?,?,?,?)`,
		id, ptype, filename, fpath, size, listener, createdAt,
	)
	return err
}

// ListPayloadHistory returns all payload records ordered by creation time.
func (db *Database) ListPayloadHistory() ([]map[string]string, error) {
	rows, err := db.conn.Query(
		`SELECT id, type, filename, filepath, size, listener, created_at FROM payload_history ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []map[string]string
	for rows.Next() {
		var id, ptype, filename, fpath, size, listener, createdAt string
		if err := rows.Scan(&id, &ptype, &filename, &fpath, &size, &listener, &createdAt); err != nil {
			continue
		}
		result = append(result, map[string]string{
			"id": id, "type": ptype, "filename": filename,
			"filepath": fpath, "size": size, "listener": listener, "created_at": createdAt,
		})
	}
	return result, rows.Err()
}

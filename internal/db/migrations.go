package db

import "strings"

func isDuplicateColumnError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "duplicate column") || strings.Contains(s, "already exists")
}

// migrate runs all schema migrations.
func (db *Database) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS agents (
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL UNIQUE,
			external_ip  TEXT NOT NULL DEFAULT '',
			internal_ip  TEXT NOT NULL DEFAULT '',
			hostname     TEXT NOT NULL,
			username     TEXT NOT NULL,
			os           TEXT NOT NULL,
			arch         TEXT NOT NULL,
			pid          INTEGER NOT NULL DEFAULT 0,
			process_name TEXT NOT NULL DEFAULT '',
			sleep        INTEGER NOT NULL DEFAULT 10,
			jitter       INTEGER NOT NULL DEFAULT 20,
			first_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			status       TEXT NOT NULL DEFAULT 'active',
			listener_id  TEXT NOT NULL DEFAULT ''
		)`,

		`CREATE TABLE IF NOT EXISTS tasks (
			id           TEXT PRIMARY KEY,
			agent_id     TEXT NOT NULL,
			type         INTEGER NOT NULL,
			args         TEXT DEFAULT '[]',
			data         BLOB DEFAULT NULL,
			status       INTEGER NOT NULL DEFAULT 0,
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			sent_at      DATETIME DEFAULT NULL,
			completed_at DATETIME DEFAULT NULL,
			FOREIGN KEY (agent_id) REFERENCES agents(id)
		)`,

		`CREATE TABLE IF NOT EXISTS task_results (
			task_id     TEXT PRIMARY KEY,
			agent_id    TEXT NOT NULL,
			output      BLOB DEFAULT NULL,
			error       TEXT DEFAULT '',
			received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (task_id) REFERENCES tasks(id),
			FOREIGN KEY (agent_id) REFERENCES agents(id)
		)`,

		`CREATE TABLE IF NOT EXISTS listeners (
			id         TEXT PRIMARY KEY,
			name       TEXT NOT NULL UNIQUE,
			type       TEXT NOT NULL,
			bind_addr  TEXT NOT NULL,
			profile_id TEXT NOT NULL DEFAULT 'default',
			tls_cert   TEXT DEFAULT '',
			tls_key    TEXT DEFAULT '',
			status     TEXT NOT NULL DEFAULT 'stopped',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS loot (
			id         TEXT PRIMARY KEY,
			agent_id   TEXT NOT NULL,
			task_id    TEXT NOT NULL,
			type       TEXT NOT NULL,
			name       TEXT NOT NULL,
			data       BLOB NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (agent_id) REFERENCES agents(id),
			FOREIGN KEY (task_id) REFERENCES tasks(id)
		)`,

		`CREATE TABLE IF NOT EXISTS listener_presets (
			id         TEXT PRIMARY KEY,
			name       TEXT NOT NULL UNIQUE,
			type       TEXT NOT NULL DEFAULT 'http',
			bind_addr  TEXT NOT NULL,
			profile    TEXT NOT NULL DEFAULT 'default',
			tls_cert   TEXT DEFAULT '',
			tls_key    TEXT DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE INDEX IF NOT EXISTS idx_tasks_agent_status ON tasks(agent_id, status)`,
		`CREATE INDEX IF NOT EXISTS idx_loot_agent ON loot(agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_task_results_agent ON task_results(agent_id)`,

		// v2 migrations — safe to re-run (ALTER TABLE is idempotent via IGNORE)
		`ALTER TABLE agents ADD COLUMN tags TEXT NOT NULL DEFAULT ''`,
	}

	for _, m := range migrations {
		if _, err := db.conn.Exec(m); err != nil {
			// Ignore "duplicate column" errors from ALTER TABLE on existing DBs
			if !isDuplicateColumnError(err) {
				return err
			}
		}
	}

	return nil
}

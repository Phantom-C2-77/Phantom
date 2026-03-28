package db

import (
	"database/sql"
	"time"
)

// ListenerPreset is a saved listener configuration for quick reuse.
type ListenerPreset struct {
	ID        string
	Name      string
	Type      string
	BindAddr  string
	Profile   string
	TLSCert   string
	TLSKey    string
	CreatedAt time.Time
}

func (db *Database) InsertPreset(p *ListenerPreset) error {
	_, err := db.conn.Exec(`
		INSERT INTO listener_presets (id, name, type, bind_addr, profile, tls_cert, tls_key, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.Type, p.BindAddr, p.Profile, p.TLSCert, p.TLSKey, p.CreatedAt,
	)
	return err
}

func (db *Database) ListPresets() ([]*ListenerPreset, error) {
	rows, err := db.conn.Query(`SELECT id, name, type, bind_addr, profile, tls_cert, tls_key, created_at FROM listener_presets ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var presets []*ListenerPreset
	for rows.Next() {
		p := &ListenerPreset{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Type, &p.BindAddr, &p.Profile, &p.TLSCert, &p.TLSKey, &p.CreatedAt); err != nil {
			return nil, err
		}
		presets = append(presets, p)
	}
	return presets, rows.Err()
}

func (db *Database) GetPresetByName(name string) (*ListenerPreset, error) {
	p := &ListenerPreset{}
	err := db.conn.QueryRow(`SELECT id, name, type, bind_addr, profile, tls_cert, tls_key, created_at FROM listener_presets WHERE name = ?`, name).
		Scan(&p.ID, &p.Name, &p.Type, &p.BindAddr, &p.Profile, &p.TLSCert, &p.TLSKey, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

func (db *Database) DeletePreset(name string) error {
	_, err := db.conn.Exec(`DELETE FROM listener_presets WHERE name = ?`, name)
	return err
}

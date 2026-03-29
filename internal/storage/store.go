package storage

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if path == "" {
		path = "relay.db"
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	// TODO: configure SQLite pragmas and connection pool settings for gateway write workload.
	return &Store{db: db}, nil
}

func (s *Store) Migrate() error {
	// TODO: evolve schema migrations with versioned steps and rollback handling.
	const schema = `
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp DATETIME NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status INTEGER NOT NULL,
  latency_ms INTEGER NOT NULL,
  backend_id TEXT,
  client_ip TEXT,
  route_id TEXT
);
CREATE TABLE IF NOT EXISTS metrics_summary (
  route_id TEXT NOT NULL,
  window_start DATETIME NOT NULL,
  window_secs INTEGER NOT NULL,
  snapshot_json BLOB NOT NULL,
  updated_at DATETIME NOT NULL,
  PRIMARY KEY (route_id, window_start, window_secs)
);
CREATE TABLE IF NOT EXISTS backends (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  healthy BOOLEAN NOT NULL,
  last_check DATETIME
);
`
	_, err := s.db.Exec(schema)
	return err
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

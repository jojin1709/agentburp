// Package db persists entries/findings/identities/audit events in SQLite
// via modernc.org/sqlite — a pure-Go driver, so no CGO and no native
// toolchain is needed. The public API (Open, Close, InsertEntry, Search, ...)
// is the same shape it always was, so no other package had to change.
//
// The database lives in a single file (see workspace.DBPath) in WAL mode so
// the long-running proxy process and short-lived CLI invocations can read
// and write concurrently. A mutex serializes writes inside this process;
// SQLite's own locking handles cross-process access.
package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jojin1709/agentburp/internal/model"
	_ "modernc.org/sqlite"
)

const timeLayout = time.RFC3339Nano

type DB struct {
	path   string
	sqlDB  *sql.DB
	mu     sync.Mutex
}

var schema = []string{
	`CREATE TABLE IF NOT EXISTS entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		method TEXT NOT NULL,
		url TEXT NOT NULL,
		host TEXT NOT NULL,
		req_headers TEXT NOT NULL DEFAULT '{}',
		req_body TEXT NOT NULL DEFAULT '',
		status INTEGER NOT NULL DEFAULT 0,
		resp_headers TEXT NOT NULL DEFAULT '{}',
		resp_body TEXT NOT NULL DEFAULT '',
		length INTEGER NOT NULL DEFAULT 0,
		duration_ms INTEGER NOT NULL DEFAULT 0,
		identity TEXT NOT NULL DEFAULT '',
		workspace TEXT NOT NULL DEFAULT '',
		tags TEXT NOT NULL DEFAULT '[]'
	)`,
	`CREATE INDEX IF NOT EXISTS idx_entries_ws_host ON entries(workspace, host)`,
	`CREATE INDEX IF NOT EXISTS idx_entries_status ON entries(status)`,
	`CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		module TEXT NOT NULL,
		entry_id INTEGER NOT NULL DEFAULT 0,
		title TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '',
		confidence TEXT NOT NULL DEFAULT 'low',
		workspace TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_findings_ws ON findings(workspace, entry_id)`,
	`CREATE TABLE IF NOT EXISTS identities (
		name TEXT PRIMARY KEY,
		headers TEXT NOT NULL DEFAULT '{}',
		notes TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		action TEXT NOT NULL,
		reason TEXT NOT NULL DEFAULT '',
		entry_id INTEGER NOT NULL DEFAULT 0,
		workspace TEXT NOT NULL DEFAULT ''
	)`,
}

var pragmas = []string{
	`PRAGMA journal_mode=WAL`,
	`PRAGMA synchronous=NORMAL`,
	`PRAGMA busy_timeout=10000`,
	`PRAGMA foreign_keys=ON`,
}

// Open connects to (creating if needed) the SQLite database at path and
// migrates a legacy JSON-file store of the same basename, if one is present
// and the database is still empty.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	handle, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	// modernc's driver is safe for concurrent use, but serialize writers
	// through a single connection to keep write ordering predictable.
	handle.SetMaxOpenConns(4)
	handle.SetMaxIdleConns(4)
	handle.SetConnMaxLifetime(0)

	d := &DB{path: path, sqlDB: handle}
	for _, p := range append(append([]string{}, pragmas...), schema...) {
		if _, err := d.sqlDB.Exec(p); err != nil {
			handle.Close()
			return nil, fmt.Errorf("init sqlite %s: %w", path, err)
		}
	}
	if err := d.importLegacyIfEmpty(); err != nil {
		handle.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sqlDB.Close()
}

func (d *DB) InsertEntry(e *model.Entry) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	reqH, err := marshalHeaders(e.ReqHeaders)
	if err != nil {
		return 0, err
	}
	respH, err := marshalHeaders(e.RespHeaders)
	if err != nil {
		return 0, err
	}
	tags, err := json.Marshal(e.Tags)
	if err != nil {
		return 0, err
	}
	res, err := d.sqlDB.Exec(
		`INSERT INTO entries (timestamp, method, url, host, req_headers, req_body,
			status, resp_headers, resp_body, length, duration_ms, identity, workspace, tags)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.Timestamp.Format(timeLayout), e.Method, e.URL, e.Host, reqH, e.ReqBody,
		e.Status, respH, e.RespBody, e.Length, e.DurationMS, e.Identity, e.Workspace, string(tags),
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	e.ID = id
	return id, nil
}

func (d *DB) GetEntry(id int64) (*model.Entry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.sqlDB.QueryRow(
		`SELECT id, timestamp, method, url, host, req_headers, req_body, status,
			resp_headers, resp_body, length, duration_ms, identity, workspace, tags
		 FROM entries WHERE id = ?`, id)
	e, err := scanEntry(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("entry %d not found", id)
	}
	return e, err
}

// SearchOpts filters for listing/searching history.
type SearchOpts struct {
	Workspace string
	Host      string
	Method    string
	Status    int // 0 = any
	BodyRegex string
	Limit     int
}

func (d *DB) Search(o SearchOpts) ([]*model.Entry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var conds []string
	var args []interface{}
	if o.Workspace != "" {
		conds = append(conds, `workspace = ?`)
		args = append(args, o.Workspace)
	}
	if o.Host != "" {
		// case-insensitive substring, matching the previous in-memory filter
		conds = append(conds, `instr(lower(host), lower(?)) > 0`)
		args = append(args, o.Host)
	}
	if o.Method != "" {
		conds = append(conds, `lower(method) = lower(?)`)
		args = append(args, o.Method)
	}
	if o.Status != 0 {
		conds = append(conds, `status = ?`)
		args = append(args, o.Status)
	}
	if o.BodyRegex != "" {
		// case-sensitive substring over request OR response body
		conds = append(conds, `(instr(req_body, ?) > 0 OR instr(resp_body, ?) > 0)`)
		args = append(args, o.BodyRegex, o.BodyRegex)
	}
	q := `SELECT id, timestamp, method, url, host, req_headers, req_body, status,
			resp_headers, resp_body, length, duration_ms, identity, workspace, tags
	      FROM entries`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY id DESC"
	if o.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", o.Limit)
	}

	rows, err := d.sqlDB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) InsertFinding(f *model.Finding) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now()
	}
	res, err := d.sqlDB.Exec(
		`INSERT INTO findings (timestamp, module, entry_id, title, detail, confidence, workspace)
		 VALUES (?,?,?,?,?,?,?)`,
		f.Timestamp.Format(timeLayout), f.Module, f.EntryID, f.Title, f.Detail, f.Confidence, f.Workspace,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	f.ID = id
	return id, nil
}

// ListFindings returns findings newest-first. An empty minConfidence means
// "all"; otherwise it is a floor ("low" <= "medium" <= "high").
func (d *DB) ListFindings(workspace string, minConfidence string) ([]*model.Finding, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	conds := []string{`1=1`}
	args := []interface{}{}
	if workspace != "" {
		conds = append(conds, `workspace = ?`)
		args = append(args, workspace)
	}
	if rank, ok := confidenceRank(minConfidence); ok {
		conds = append(conds, `CASE lower(confidence)
			WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END >= ?`)
		args = append(args, rank)
	}
	q := `SELECT id, timestamp, module, entry_id, title, detail, confidence, workspace
	      FROM findings WHERE ` + strings.Join(conds, " AND ") + ` ORDER BY id DESC`

	rows, err := d.sqlDB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.Finding
	for rows.Next() {
		f := &model.Finding{}
		var ts string
		if err := rows.Scan(&f.ID, &ts, &f.Module, &f.EntryID, &f.Title, &f.Detail, &f.Confidence, &f.Workspace); err != nil {
			return nil, err
		}
		f.Timestamp, _ = time.Parse(timeLayout, ts)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (d *DB) UpsertIdentity(idn *model.Identity) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	h, err := marshalHeaders(idn.Headers)
	if err != nil {
		return err
	}
	_, err = d.sqlDB.Exec(
		`INSERT INTO identities (name, headers, notes) VALUES (?,?,?)
		 ON CONFLICT(name) DO UPDATE SET headers = excluded.headers, notes = excluded.notes`,
		idn.Name, h, idn.Notes,
	)
	return err
}

func (d *DB) GetIdentity(name string) (*model.Identity, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var h, notes string
	err := d.sqlDB.QueryRow(`SELECT headers, notes FROM identities WHERE name = ?`, name).Scan(&h, &notes)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("identity %q not found", name)
	}
	if err != nil {
		return nil, err
	}
	out := &model.Identity{Name: name, Notes: notes}
	if err := json.Unmarshal([]byte(h), &out.Headers); err != nil {
		return nil, err
	}
	return out, nil
}

func (d *DB) LogAudit(ev *model.AuditEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	res, err := d.sqlDB.Exec(
		`INSERT INTO audit_log (timestamp, action, reason, entry_id, workspace) VALUES (?,?,?,?,?)`,
		ev.Timestamp.Format(timeLayout), ev.Action, ev.Reason, ev.EntryID, ev.Workspace,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	ev.ID = id
	return nil
}

// ---------- helpers ----------

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanEntry(r rowScanner) (*model.Entry, error) {
	e := &model.Entry{}
	var ts, reqH, respH, tags string
	err := r.Scan(&e.ID, &ts, &e.Method, &e.URL, &e.Host, &reqH, &e.ReqBody, &e.Status,
		&respH, &e.RespBody, &e.Length, &e.DurationMS, &e.Identity, &e.Workspace, &tags)
	if err != nil {
		return nil, err
	}
	e.Timestamp, _ = time.Parse(timeLayout, ts)
	if err := json.Unmarshal([]byte(reqH), &e.ReqHeaders); err != nil {
		return nil, fmt.Errorf("entry %d: bad req_headers json: %w", e.ID, err)
	}
	if err := json.Unmarshal([]byte(respH), &e.RespHeaders); err != nil {
		return nil, fmt.Errorf("entry %d: bad resp_headers json: %w", e.ID, err)
	}
	if tags != "" && tags != "[]" {
		if err := json.Unmarshal([]byte(tags), &e.Tags); err != nil {
			return nil, fmt.Errorf("entry %d: bad tags json: %w", e.ID, err)
		}
	}
	return e, nil
}

func marshalHeaders(h map[string]string) (string, error) {
	if h == nil {
		h = map[string]string{}
	}
	b, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func confidenceRank(s string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return 1, true
	case "medium":
		return 2, true
	case "high":
		return 3, true
	default:
		return 0, false
	}
}

// legacyStore mirrors the pre-SQLite JSON file layout, used only to migrate
// an existing history.json into the new SQLite database on first open.
type legacyStore struct {
	Entries     []*model.Entry      `json:"entries"`
	Findings    []*model.Finding    `json:"findings"`
	Identities  []*model.Identity   `json:"identities"`
	Audit       []*model.AuditEvent `json:"audit"`
}

func (d *DB) importLegacyIfEmpty() error {
	legacy := strings.TrimSuffix(d.path, ".db") + ".json"
	if !strings.HasSuffix(d.path, ".db") || legacy == d.path {
		return nil
	}
	var n int
	if err := d.sqlDB.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	b, err := os.ReadFile(legacy)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var s legacyStore
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("legacy db %s: %w", legacy, err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.sqlDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	insEntry, err := tx.Prepare(
		`INSERT INTO entries (id, timestamp, method, url, host, req_headers, req_body,
			status, resp_headers, resp_body, length, duration_ms, identity, workspace, tags)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer insEntry.Close()
	for _, e := range s.Entries {
		reqH, err := marshalHeaders(e.ReqHeaders)
		if err != nil {
			return err
		}
		respH, err := marshalHeaders(e.RespHeaders)
		if err != nil {
			return err
		}
		tags, err := json.Marshal(e.Tags)
		if err != nil {
			return err
		}
		ts := e.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		if _, err := insEntry.Exec(e.ID, ts.Format(timeLayout), e.Method, e.URL, e.Host,
			reqH, e.ReqBody, e.Status, respH, e.RespBody, e.Length, e.DurationMS,
			e.Identity, e.Workspace, string(tags)); err != nil {
			return err
		}
	}

	insFinding, err := tx.Prepare(
		`INSERT INTO findings (id, timestamp, module, entry_id, title, detail, confidence, workspace)
		 VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer insFinding.Close()
	for _, f := range s.Findings {
		ts := f.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		if _, err := insFinding.Exec(f.ID, ts.Format(timeLayout), f.Module, f.EntryID,
			f.Title, f.Detail, f.Confidence, f.Workspace); err != nil {
			return err
		}
	}

	for _, idn := range s.Identities {
		h, err := marshalHeaders(idn.Headers)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(
			`INSERT INTO identities (name, headers, notes) VALUES (?,?,?)
			 ON CONFLICT(name) DO UPDATE SET headers = excluded.headers, notes = excluded.notes`,
			idn.Name, h, idn.Notes); err != nil {
			return err
		}
	}

	insAudit, err := tx.Prepare(
		`INSERT INTO audit_log (id, timestamp, action, reason, entry_id, workspace) VALUES (?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer insAudit.Close()
	for _, ev := range s.Audit {
		ts := ev.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		if _, err := insAudit.Exec(ev.ID, ts.Format(timeLayout), ev.Action, ev.Reason,
			ev.EntryID, ev.Workspace); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return os.Rename(legacy, legacy+".migrated")
}

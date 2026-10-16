package model

import "time"

// Entry is one captured HTTP transaction.
type Entry struct {
	ID         int64             `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Host       string            `json:"host"`
	ReqHeaders map[string]string `json:"req_headers"`
	ReqBody    string            `json:"req_body"`
	Status     int               `json:"status"`
	RespHeaders map[string]string `json:"resp_headers"`
	RespBody   string            `json:"resp_body"`
	Length     int               `json:"length"`
	DurationMS int64             `json:"duration_ms"`
	Identity   string            `json:"identity,omitempty"`
	Workspace  string            `json:"workspace"`
	Tags       []string          `json:"tags,omitempty"`
}

// Finding is a scanner-reported potential vulnerability.
type Finding struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Module     string    `json:"module"` // idor, ssrf, open_redirect, auth_bypass, jwt, cors, takeover
	EntryID    int64     `json:"entry_id"`
	Title      string    `json:"title"`
	Detail     string    `json:"detail"`
	Confidence string    `json:"confidence"` // low, medium, high
	Workspace  string    `json:"workspace"`
}

// Identity is a named session/credential set the agent can switch between.
type Identity struct {
	Name    string            `json:"name"`
	Headers map[string]string `json:"headers"` // e.g. Authorization, Cookie
	Notes   string            `json:"notes,omitempty"`
}

// AuditEvent logs what the agent decided and why, separate from raw request history.
type AuditEvent struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason"`
	EntryID   int64     `json:"entry_id,omitempty"`
	Workspace string    `json:"workspace"`
}

// WSFrame represents an intercepted WebSocket message frame.
type WSFrame struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	EntryID    int64     `json:"entry_id"`
	Direction  string    `json:"direction"` // "client->server" or "server->client"
	Opcode     int       `json:"opcode"`    // 1=text, 2=binary, 8=close, 9=ping, 10=pong
	OpcodeName string    `json:"opcode_name"`
	Length     int       `json:"length"`
	Payload    string    `json:"payload"`
	Workspace  string    `json:"workspace"`
}


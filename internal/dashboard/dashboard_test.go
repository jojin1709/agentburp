package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/jojin1709/agentburp/internal/db"
	"github.com/jojin1709/agentburp/internal/model"
	"github.com/jojin1709/agentburp/internal/oast"
	"github.com/jojin1709/agentburp/internal/scope"
)

func TestDashboardEndpoints(t *testing.T) {
	tmpDir := t.TempDir()
	database, err := db.Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer database.Close()

	// Seed test entry
	e := &model.Entry{
		Timestamp:   time.Now(),
		Method:      "GET",
		URL:         "https://api.target.com/users?id=1",
		Host:        "api.target.com",
		ReqHeaders:  map[string]string{"Accept": "application/json"},
		ReqBody:     "",
		Status:      200,
		RespHeaders: map[string]string{"Content-Type": "application/json"},
		RespBody:    `{"id":1,"name":"Alice"}`,
		Length:      23,
		DurationMS:  12,
		Workspace:   "default",
	}
	id, err := database.InsertEntry(e)
	if err != nil {
		t.Fatalf("failed to insert entry: %v", err)
	}

	scopeCfg := &scope.Config{
		Workspace:  "default",
		AllowHosts: []string{"api.target.com"},
	}

	oastSrv := oast.NewServer("127.0.0.1:0", "http://127.0.0.1:9998")

	srv := NewServer("127.0.0.1:8889", database, scopeCfg, "default", oastSrv)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. GET / (Dashboard HTML)
	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("expected 200 OK for dashboard HTML, got %d", res.StatusCode)
	}
	res.Body.Close()

	// 2. GET /api/history
	res, err = http.Get(ts.URL + "/api/history")
	if err != nil {
		t.Fatalf("GET /api/history failed: %v", err)
	}
	var entries []*model.Entry
	_ = json.NewDecoder(res.Body).Decode(&entries)
	res.Body.Close()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	// 3. GET /api/history/:id
	res, err = http.Get(ts.URL + "/api/history/" + string(rune('0'+id)))
	if err != nil {
		t.Fatalf("GET /api/history/:id failed: %v", err)
	}
	var detail map[string]any
	_ = json.NewDecoder(res.Body).Decode(&detail)
	res.Body.Close()
	if detail["curl"] == nil {
		t.Fatalf("expected curl field in entry detail")
	}

	// 4. GET /api/oast/token
	res, err = http.Get(ts.URL + "/api/oast/token")
	if err != nil {
		t.Fatalf("GET /api/oast/token failed: %v", err)
	}
	var tokenResp map[string]string
	_ = json.NewDecoder(res.Body).Decode(&tokenResp)
	res.Body.Close()
	if tokenResp["token"] == "" || tokenResp["url"] == "" {
		t.Fatalf("unexpected token response: %v", tokenResp)
	}
}

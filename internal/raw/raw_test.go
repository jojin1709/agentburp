package raw

import (
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/jojin1709/agentburp/internal/db"
	"github.com/jojin1709/agentburp/internal/scope"
)

func TestReplayRaw(t *testing.T) {
	// Start target test server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Raw-Header") != "smuggle-test" {
				http.Error(w, "missing header", 400)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("raw-success"))
		}),
	}
	go server.Serve(ln)
	defer server.Close()

	tmpDir := t.TempDir()
	d, err := db.Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer d.Close()

	g := scope.NewGuard(&scope.Config{
		AllowHosts: []string{"127.0.0.1"},
	})

	rawReq := fmt.Sprintf("POST /api/raw HTTP/1.1\r\nHost: %s\r\nX-Raw-Header: smuggle-test\r\nContent-Length: 0\r\n\r\n", addr)
	entry, err := ReplayRaw(d, g, []byte(rawReq), Options{
		Target:    addr,
		Workspace: "raw_ws",
	})
	if err != nil {
		t.Fatalf("ReplayRaw failed: %v", err)
	}

	if entry.Status != 200 {
		t.Fatalf("expected status 200, got %d", entry.Status)
	}
	if entry.RespBody != "raw-success" {
		t.Fatalf("expected respBody 'raw-success', got %q", entry.RespBody)
	}
	if entry.ReqHeaders["X-Raw-Header"] != "smuggle-test" {
		t.Fatalf("missing X-Raw-Header in logged entry")
	}
}

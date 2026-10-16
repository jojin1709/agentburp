package oast

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOASTServerAndPoll(t *testing.T) {
	srv := NewServer("127.0.0.1:0", "http://127.0.0.1")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Request token
	tok, cbURL, err := RequestToken(ts.URL)
	if err != nil {
		t.Fatalf("RequestToken failed: %v", err)
	}
	if tok == "" || !strings.Contains(cbURL, tok) {
		t.Fatalf("unexpected token %q or callback URL %q", tok, cbURL)
	}

	// 2. Poll before callback -> should be empty
	events, err := Poll(ts.URL, tok)
	if err != nil {
		t.Fatalf("Poll failed: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(events))
	}

	// 3. Simulate target server making callback to /c/<token>
	targetReq, err := http.NewRequest("POST", ts.URL+"/c/"+tok+"?param=ssrf_test", strings.NewReader("blind_rce_output"))
	if err != nil {
		t.Fatalf("failed to build target request: %v", err)
	}
	targetReq.Header.Set("X-Server-Identity", "internal-backend-node-1")
	resp, err := http.DefaultClient.Do(targetReq)
	if err != nil {
		t.Fatalf("callback failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from oast receiver, got %d", resp.StatusCode)
	}

	// 4. Poll again -> should contain 1 event with details
	events, err = Poll(ts.URL, tok)
	if err != nil {
		t.Fatalf("Poll failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Token != tok {
		t.Errorf("expected token %s, got %s", tok, ev.Token)
	}
	if ev.Method != "POST" {
		t.Errorf("expected POST, got %s", ev.Method)
	}
	if ev.Body != "blind_rce_output" {
		t.Errorf("expected body 'blind_rce_output', got %s", ev.Body)
	}
	if ev.Headers["X-Server-Identity"] != "internal-backend-node-1" {
		t.Errorf("expected header 'X-Server-Identity', got %v", ev.Headers)
	}
}

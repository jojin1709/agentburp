package proxy

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jojin1709/agentburp/internal/db"
	"github.com/jojin1709/agentburp/internal/export"
	"github.com/jojin1709/agentburp/internal/model"
	"github.com/jojin1709/agentburp/internal/scope"
)

func TestProxyHeaderInjectionAndUpstreamChaining(t *testing.T) {
	// 1. Target server: records received headers and responds
	var targetReceivedHeaders http.Header
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen target: %v", err)
	}
	defer targetLn.Close()
	targetAddr := targetLn.Addr().String()

	targetServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetReceivedHeaders = r.Header.Clone()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"target_reached"}`))
		}),
	}
	go targetServer.Serve(targetLn)
	defer targetServer.Close()

	// 2. Upstream proxy server: records requests and forwards with X-Via-Upstream
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen upstream: %v", err)
	}
	defer upstreamLn.Close()
	upstreamAddr := upstreamLn.Addr().String()
	upstreamURL := "http://" + upstreamAddr

	upstreamServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Forward request to actual target URL
			outReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			for k, v := range r.Header {
				outReq.Header[k] = v
			}
			outReq.Header.Set("X-Via-Upstream", "burp-chain-verified")

			resp, err := http.DefaultTransport.RoundTrip(outReq)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			for k, v := range resp.Header {
				w.Header()[k] = v
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}),
	}
	go upstreamServer.Serve(upstreamLn)
	defer upstreamServer.Close()

	// 3. Setup agentburp DB & Scope Guard
	tmpDir := t.TempDir()
	d, err := db.Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer d.Close()

	cfg := &scope.Config{
		Workspace:     "test_ws",
		AllowHosts:    []string{"127.0.0.1", "localhost"},
		UpstreamProxy: upstreamURL,
		InjectHeaders: map[string]string{
			"X-Bug-Bounty": "jojin@intigriti.me",
		},
	}
	g := scope.NewGuard(cfg)

	// 4. Start agentburp proxy
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen proxy: %v", err)
	}
	proxyAddr := proxyLn.Addr().String()
	proxyLn.Close() // Close listener so agentburp proxy can bind to it

	srv := New(proxyAddr, d, g, "test_ws")
	go srv.ListenAndServe()
	time.Sleep(100 * time.Millisecond)

	// 5. Client sends request through agentburp proxy
	proxyParsedURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyParsedURL),
		},
	}

	reqURL := "http://" + targetAddr + "/api/v1/test"
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		t.Fatalf("failed to create req: %v", err)
	}
	req.Header.Set("User-Agent", "agentburp-tester/1.0")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request through agentburp proxy failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// 6. Verify Feature C: Header Injection reached target
	if targetReceivedHeaders.Get("X-Bug-Bounty") != "jojin@intigriti.me" {
		t.Fatalf("Feature C FAILED: expected target to receive X-Bug-Bounty 'jojin@intigriti.me', got %q", targetReceivedHeaders.Get("X-Bug-Bounty"))
	}

	// 7. Verify Feature B: Upstream Proxy Chaining reached target via upstream
	if targetReceivedHeaders.Get("X-Via-Upstream") != "burp-chain-verified" {
		t.Fatalf("Feature B FAILED: expected target to receive X-Via-Upstream 'burp-chain-verified', got %q", targetReceivedHeaders.Get("X-Via-Upstream"))
	}

	// 8. Verify SQLite History Log
	entries, err := d.Search(db.SearchOpts{Workspace: "test_ws", Limit: 10})
	if err != nil || len(entries) != 1 {
		t.Fatalf("failed to find logged entry in DB: %v (count: %d)", err, len(entries))
	}
	entry := entries[0]
	if entry.ReqHeaders["X-Bug-Bounty"] != "jojin@intigriti.me" {
		t.Fatalf("SQLite entry missing injected header: %+v", entry.ReqHeaders)
	}

	// 9. Verify Feature A: Exporter with the captured injected request
	curlCmd := export.ToCurl(entry)
	if !strings.Contains(curlCmd, "X-Bug-Bounty: jojin@intigriti.me") {
		t.Fatalf("cURL export missing injected header: %s", curlCmd)
	}

	harBytes, err := export.ToHAR([]*model.Entry{entry})
	if err != nil {
		t.Fatalf("HAR export failed: %v", err)
	}
	var har export.HARLog
	if err := json.Unmarshal(harBytes, &har); err != nil {
		t.Fatalf("HAR invalid JSON: %v", err)
	}
	foundInHAR := false
	for _, h := range har.Log.Entries[0].Request.Headers {
		if h.Name == "X-Bug-Bounty" && h.Value == "jojin@intigriti.me" {
			foundInHAR = true
			break
		}
	}
	if !foundInHAR {
		t.Fatalf("HAR export missing injected header")
	}
}

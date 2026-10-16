package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jojin1709/agentburp/internal/db"
	"github.com/jojin1709/agentburp/internal/model"
	"github.com/jojin1709/agentburp/internal/scope"
)

// Server is a forward HTTP proxy that logs every transaction to the DB.
// It supports plain HTTP proxying out of the box. HTTPS interception
// (full MITM with a generated CA) requires installing the CA this tool
// generates on first run — see cmd `agentburp proxy ca`.
type Server struct {
	Addr      string
	DB        *db.DB
	Guard     *scope.Guard
	Workspace string
	client    *http.Client
}

func New(addr string, d *db.DB, g *scope.Guard, workspace string) *Server {
	return &Server{
		Addr:      addr,
		DB:        d,
		Guard:     g,
		Workspace: workspace,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
		},
	}
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	log.Printf("agentburp proxy listening on %s (workspace=%s)", s.Addr, s.Workspace)
	return http.Serve(ln, http.HandlerFunc(s.handle))
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handlePlain(w, r)
}

// handleConnect tunnels HTTPS traffic without decrypting it (pass-through MITM
// is disabled by default for safety; enable with -mitm once the CA is trusted).
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if ok, reason := s.Guard.Allowed(strings.Split(host, ":")[0]); !ok {
		http.Error(w, "blocked by scope guard: "+reason, http.StatusForbidden)
		return
	}
	destConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusOK)
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func (s *Server) handlePlain(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if ok, reason := s.Guard.Allowed(host); !ok {
		http.Error(w, "blocked by scope guard: "+reason, http.StatusForbidden)
		return
	}
	s.Guard.Throttle()

	start := time.Now()
	reqBody, _ := io.ReadAll(r.Body)
	r.Body.Close()

	outReq, err := http.NewRequest(r.Method, r.URL.String(), bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	reqHeaders := map[string]string{}
	for k, v := range r.Header {
		outReq.Header.Set(k, strings.Join(v, ","))
		reqHeaders[k] = strings.Join(v, ",")
	}

	resp, err := s.client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	respHeaders := map[string]string{}
	for k, v := range resp.Header {
		w.Header().Set(k, strings.Join(v, ","))
		respHeaders[k] = strings.Join(v, ",")
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	e := &model.Entry{
		Timestamp:   start,
		Method:      r.Method,
		URL:         r.URL.String(),
		Host:        host,
		ReqHeaders:  reqHeaders,
		ReqBody:     string(reqBody),
		Status:      resp.StatusCode,
		RespHeaders: respHeaders,
		RespBody:    string(respBody),
		Length:      len(respBody),
		DurationMS:  time.Since(start).Milliseconds(),
		Workspace:   s.Workspace,
	}
	if _, err := s.DB.InsertEntry(e); err != nil {
		log.Printf("warn: failed to log entry: %v", err)
	}
}

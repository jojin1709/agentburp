package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jojin1709/agentburp/internal/db"
	"github.com/jojin1709/agentburp/internal/model"
	"github.com/jojin1709/agentburp/internal/scope"
)

// Options holds configuration for the proxy server.
type Options struct {
	UpstreamProxy string
	InjectHeaders map[string]string
	Quiet         bool
}

// Server is a forward HTTP proxy that logs every transaction to the DB.
type Server struct {
	Addr          string
	DB            *db.DB
	Guard         *scope.Guard
	Workspace     string
	UpstreamProxy string
	InjectHeaders map[string]string
	Quiet         bool
	client        *http.Client
	listener      net.Listener
}

func New(addr string, d *db.DB, g *scope.Guard, workspace string, opts ...Options) *Server {
	srv := &Server{
		Addr:          addr,
		DB:            d,
		Guard:         g,
		Workspace:     workspace,
		InjectHeaders: make(map[string]string),
	}

	// 1. Pull defaults from Guard's scope config if available
	if g != nil && g.Config() != nil {
		if g.Config().UpstreamProxy != "" {
			srv.UpstreamProxy = g.Config().UpstreamProxy
		}
		for k, v := range g.Config().InjectHeaders {
			srv.InjectHeaders[k] = v
		}
	}

	// 2. Override with explicit CLI Options
	if len(opts) > 0 {
		if opts[0].UpstreamProxy != "" {
			srv.UpstreamProxy = opts[0].UpstreamProxy
		}
		for k, v := range opts[0].InjectHeaders {
			srv.InjectHeaders[k] = v
		}
		srv.Quiet = opts[0].Quiet
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}

	if srv.UpstreamProxy != "" {
		if u, err := url.Parse(srv.UpstreamProxy); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}

	srv.client = &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}

	return srv
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.listener = ln
	if s.UpstreamProxy != "" {
		log.Printf("agentburp proxy listening on %s (upstream=%s, workspace=%s)", s.Addr, s.UpstreamProxy, s.Workspace)
	} else {
		log.Printf("agentburp proxy listening on %s (workspace=%s)", s.Addr, s.Workspace)
	}
	return http.Serve(ln, http.HandlerFunc(s.handle))
}

func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handlePlain(w, r)
}

// handleConnect tunnels HTTPS traffic. If an upstream proxy is configured,
// it dials the upstream proxy and negotiates CONNECT before tunneling.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if ok, reason := s.Guard.Allowed(strings.Split(host, ":")[0]); !ok {
		if !s.Quiet {
			log.Printf("[BLOCKED] CONNECT %s — %s", host, reason)
		}
		http.Error(w, "blocked by scope guard: "+reason, http.StatusForbidden)
		return
	}

	var destConn net.Conn
	var err error

	if s.UpstreamProxy != "" {
		u, parseErr := url.Parse(s.UpstreamProxy)
		if parseErr != nil {
			http.Error(w, "invalid upstream proxy: "+parseErr.Error(), http.StatusBadGateway)
			return
		}
		targetAddr := u.Host
		if !strings.Contains(targetAddr, ":") {
			targetAddr += ":8080"
		}
		destConn, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
		if err != nil {
			http.Error(w, "failed to dial upstream proxy: "+err.Error(), http.StatusBadGateway)
			return
		}
		// Send CONNECT to upstream proxy
		fmt.Fprintf(destConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
		br := bufio.NewReader(destConn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil || resp.StatusCode != http.StatusOK {
			destConn.Close()
			status := http.StatusBadGateway
			if resp != nil && resp.StatusCode != 0 {
				status = resp.StatusCode
			}
			http.Error(w, "upstream proxy rejected CONNECT tunnel", status)
			return
		}
	} else {
		destConn, err = net.DialTimeout("tcp", host, 10*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	if !s.Quiet {
		log.Printf("[TUNNEL]  CONNECT %s (200 OK)", host)
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		destConn.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		destConn.Close()
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
		if !s.Quiet {
			log.Printf("[BLOCKED] %-6s http://%s%s — %s", r.Method, host, r.URL.Path, reason)
		}
		http.Error(w, "blocked by scope guard: "+reason, http.StatusForbidden)
		return
	}
	s.Guard.Throttle()

	start := time.Now()
	reqBody, _ := io.ReadAll(r.Body)
	r.Body.Close()

	reqURL := r.URL.String()
	if !strings.HasPrefix(reqURL, "http://") && !strings.HasPrefix(reqURL, "https://") {
		reqURL = "http://" + host + reqURL
	}

	outReq, err := http.NewRequest(r.Method, reqURL, bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	outReq.RequestURI = ""

	reqHeaders := map[string]string{}
	for k, v := range r.Header {
		val := strings.Join(v, ", ")
		outReq.Header.Set(k, val)
		reqHeaders[k] = val
	}

	// Feature C: Inject configured bug bounty / auth headers
	for k, v := range s.InjectHeaders {
		outReq.Header.Set(k, v)
		reqHeaders[k] = v
	}

	// Match & Replace for request headers
	if s.Guard != nil && s.Guard.Config() != nil {
		for k, v := range reqHeaders {
			newVal := s.Guard.Config().ApplyMatchReplace("request_header", v)
			if newVal == "" && v != "" {
				outReq.Header.Del(k)
				delete(reqHeaders, k)
			} else if newVal != v {
				outReq.Header.Set(k, newVal)
				reqHeaders[k] = newVal
			}
		}
	}

	// Match & Replace for request body
	if s.Guard != nil && s.Guard.Config() != nil && len(reqBody) > 0 {
		modBody := s.Guard.Config().ApplyMatchReplace("request_body", string(reqBody))
		if modBody != string(reqBody) {
			reqBody = []byte(modBody)
			outReq.Body = io.NopCloser(bytes.NewReader(reqBody))
			outReq.ContentLength = int64(len(reqBody))
		}
	}

	// Hop-by-hop headers cleanup
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authenticate")
	outReq.Header.Del("Proxy-Authorization")

	resp, err := s.client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	respHeaders := map[string]string{}
	for k, v := range resp.Header {
		val := strings.Join(v, ", ")
		w.Header().Set(k, val)
		respHeaders[k] = val
	}

	// Match & Replace for response headers
	if s.Guard != nil && s.Guard.Config() != nil {
		for k, v := range respHeaders {
			newVal := s.Guard.Config().ApplyMatchReplace("response_header", v)
			if newVal == "" && v != "" {
				w.Header().Del(k)
				delete(respHeaders, k)
			} else if newVal != v {
				w.Header().Set(k, newVal)
				respHeaders[k] = newVal
			}
		}
	}

	// Match & Replace for response body
	if s.Guard != nil && s.Guard.Config() != nil && len(respBody) > 0 {
		modResp := s.Guard.Config().ApplyMatchReplace("response_body", string(respBody))
		if modResp != string(respBody) {
			respBody = []byte(modResp)
		}
	}

	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	e := &model.Entry{
		Timestamp:   start,
		Method:      r.Method,
		URL:         reqURL,
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
	if !s.Quiet {
		log.Printf("[%d] %-6s %s (%d B, %dms)", resp.StatusCode, r.Method, reqURL, len(respBody), e.DurationMS)
	}
}

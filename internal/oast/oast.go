// Package oast provides an Out-of-Band Application Security Testing (OAST)
// collaborator server and polling client for verifying blind SSRF, blind XSS,
// and blind command injection.
package oast

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Interaction records an incoming callback from a target server.
type Interaction struct {
	ID        int64             `json:"id"`
	Token     string            `json:"token"`
	ClientIP  string            `json:"client_ip"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Timestamp time.Time         `json:"timestamp"`
}

// Server is a local or remote OAST receiver.
type Server struct {
	addr         string
	publicDomain string
	mu           sync.RWMutex
	interactions []*Interaction
	idSeq        int64
	httpServer   *http.Server
}

// NewServer initializes a new OAST server.
func NewServer(addr, publicDomain string) *Server {
	if publicDomain == "" {
		publicDomain = addr
	}
	return &Server{
		addr:         addr,
		publicDomain: publicDomain,
	}
}

// GenerateToken produces a cryptographically random correlation token.
func GenerateToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// URLForToken returns the callback URL for a given token.
func (s *Server) URLForToken(token string) string {
	host := s.publicDomain
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "http://" + host
	}
	return fmt.Sprintf("%s/c/%s", strings.TrimRight(host, "/"), token)
}

// Handler returns the HTTP handler for the OAST server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// API endpoints for polling
	mux.HandleFunc("/api/token", func(w http.ResponseWriter, r *http.Request) {
		tok := GenerateToken()
		resp := map[string]string{
			"token": tok,
			"url":   s.URLForToken(tok),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/poll", func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("token")
		s.mu.RLock()
		defer s.mu.RUnlock()

		var matched []*Interaction
		for _, in := range s.interactions {
			if tok == "" || in.Token == tok {
				matched = append(matched, in)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(matched)
	})

	// Callback receiver
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		var token string

		if strings.HasPrefix(path, "/c/") {
			parts := strings.Split(strings.TrimPrefix(path, "/c/"), "/")
			if len(parts) > 0 {
				token = parts[0]
			}
		}
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" {
			token = r.URL.Query().Get("id")
		}

		headers := make(map[string]string)
		for k, v := range r.Header {
			headers[k] = strings.Join(v, ", ")
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 32*1024))

		s.mu.Lock()
		s.idSeq++
		interaction := &Interaction{
			ID:        s.idSeq,
			Token:     token,
			ClientIP:  r.RemoteAddr,
			Method:    r.Method,
			URL:       r.URL.String(),
			Headers:   headers,
			Body:      string(bodyBytes),
			Timestamp: time.Now(),
		}
		s.interactions = append(s.interactions, interaction)
		s.mu.Unlock()

		w.Header().Set("Server", "agentburp-collaborator")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})

	return mux
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	s.httpServer = &http.Server{
		Addr:    s.addr,
		Handler: s.Handler(),
	}
	return s.httpServer.ListenAndServe()
}

// Close stops the OAST server.
func (s *Server) Close() error {
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

// Poll checks for interactions matching the given token against a running OAST server.
func Poll(serverBaseURL, token string) ([]*Interaction, error) {
	url := fmt.Sprintf("%s/api/poll", strings.TrimRight(serverBaseURL, "/"))
	if token != "" {
		url += "?token=" + token
	}
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("poll oast server: %w", err)
	}
	defer resp.Body.Close()

	var out []*Interaction
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode oast poll response: %w", err)
	}
	return out, nil
}

// RequestToken requests a new correlation token from a running OAST server.
func RequestToken(serverBaseURL string) (token, callbackURL string, err error) {
	url := fmt.Sprintf("%s/api/token", strings.TrimRight(serverBaseURL, "/"))
	resp, err := http.Get(url)
	if err != nil {
		return "", "", fmt.Errorf("request oast token: %w", err)
	}
	defer resp.Body.Close()

	var res struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", "", fmt.Errorf("decode token response: %w", err)
	}
	return res.Token, res.URL, nil
}

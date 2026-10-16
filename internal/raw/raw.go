package raw

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jojin1709/agentburp/internal/db"
	"github.com/jojin1709/agentburp/internal/model"
	"github.com/jojin1709/agentburp/internal/scope"
)

// Options holds configurations for raw HTTP replaying.
type Options struct {
	UseTLS    bool
	Target    string // host:port override
	Workspace string
}

// ReplayRaw sends exact raw HTTP request bytes directly over a TCP or TLS connection.
func ReplayRaw(d *db.DB, g *scope.Guard, rawData []byte, opts Options) (*model.Entry, error) {
	// Parse the raw request to extract metadata (without modifying bytes)
	parsedReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(rawData)))
	if err != nil {
		return nil, fmt.Errorf("malformed raw HTTP request: %w", err)
	}

	host := parsedReq.Host
	if host == "" && opts.Target != "" {
		host = opts.Target
	}
	if host == "" {
		return nil, fmt.Errorf("raw request missing Host header and no --target specified")
	}

	hostOnly := strings.Split(host, ":")[0]
	if ok, reason := g.Allowed(hostOnly); !ok {
		return nil, fmt.Errorf("out of scope: %s", reason)
	}
	g.Throttle()

	targetAddr := host
	if opts.Target != "" {
		targetAddr = opts.Target
	}
	if !strings.Contains(targetAddr, ":") {
		if opts.UseTLS {
			targetAddr += ":443"
		} else {
			targetAddr += ":80"
		}
	}

	start := time.Now()
	var conn net.Conn
	if opts.UseTLS {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", targetAddr, &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         hostOnly,
		})
	} else {
		conn, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("dial target %q: %w", targetAddr, err)
	}
	defer conn.Close()

	// Write raw bytes directly to socket
	if _, err := conn.Write(rawData); err != nil {
		return nil, fmt.Errorf("write raw request: %w", err)
	}

	// Read response
	resp, err := http.ReadResponse(bufio.NewReader(conn), parsedReq)
	if err != nil {
		return nil, fmt.Errorf("read raw response: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	// Collect request headers
	reqHeaders := make(map[string]string)
	for k, v := range parsedReq.Header {
		reqHeaders[k] = strings.Join(v, ", ")
	}
	if parsedReq.Host != "" {
		reqHeaders["Host"] = parsedReq.Host
	}

	// Read request body if present
	reqBodyBytes, _ := io.ReadAll(parsedReq.Body)

	// Collect response headers
	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		respHeaders[k] = strings.Join(v, ", ")
	}

	scheme := "http"
	if opts.UseTLS {
		scheme = "https"
	}
	fullURL := fmt.Sprintf("%s://%s%s", scheme, host, parsedReq.URL.RequestURI())

	entry := &model.Entry{
		Timestamp:   start,
		Method:      parsedReq.Method,
		URL:         fullURL,
		Host:        host,
		ReqHeaders:  reqHeaders,
		ReqBody:     string(reqBodyBytes),
		Status:      resp.StatusCode,
		RespHeaders: respHeaders,
		RespBody:    string(respBody),
		Length:      len(respBody),
		DurationMS:  time.Since(start).Milliseconds(),
		Workspace:   opts.Workspace,
		Tags:        []string{"raw_replay"},
	}

	newID, err := d.InsertEntry(entry)
	if err != nil {
		return nil, fmt.Errorf("log raw entry to DB: %w", err)
	}
	entry.ID = newID
	return entry, nil
}

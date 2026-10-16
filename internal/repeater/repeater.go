package repeater

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/jojin1709/agentburp/internal/db"
	"github.com/jojin1709/agentburp/internal/model"
	"github.com/jojin1709/agentburp/internal/scope"
)

// Options for replaying a stored request.
type Options struct {
	SetHeaders  map[string]string // override/add headers
	RemoveHeaders []string
	Body        string // override body; empty = keep original
	Identity    *model.Identity // apply identity headers on top
	Workspace   string
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

// Replay re-sends entry id with modifications, logs the result as a new entry, and returns it.
func Replay(d *db.DB, g *scope.Guard, id int64, o Options) (*model.Entry, error) {
	orig, err := d.GetEntry(id)
	if err != nil {
		return nil, err
	}
	if ok, reason := g.Allowed(orig.Host); !ok {
		return nil, &ScopeError{reason}
	}
	g.Throttle()

	body := orig.ReqBody
	if o.Body != "" {
		body = o.Body
	}

	req, err := http.NewRequest(orig.Method, orig.URL, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}
	for k, v := range orig.ReqHeaders {
		req.Header.Set(k, v)
	}
	if o.Identity != nil {
		for k, v := range o.Identity.Headers {
			req.Header.Set(k, v)
		}
	}
	for k, v := range o.SetHeaders {
		req.Header.Set(k, v)
	}
	for _, k := range o.RemoveHeaders {
		req.Header.Del(k)
	}

	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	respHeaders := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}
	reqHeaders := map[string]string{}
	for k, v := range req.Header {
		if len(v) > 0 {
			reqHeaders[k] = v[0]
		}
	}

	identityName := ""
	if o.Identity != nil {
		identityName = o.Identity.Name
	}

	newEntry := &model.Entry{
		Timestamp:   start,
		Method:      orig.Method,
		URL:         orig.URL,
		Host:        orig.Host,
		ReqHeaders:  reqHeaders,
		ReqBody:     body,
		Status:      resp.StatusCode,
		RespHeaders: respHeaders,
		RespBody:    string(respBody),
		Length:      len(respBody),
		DurationMS:  time.Since(start).Milliseconds(),
		Identity:    identityName,
		Workspace:   o.Workspace,
		Tags:        []string{"repeated", "from:" + itoa(id)},
	}
	newID, err := d.InsertEntry(newEntry)
	if err != nil {
		return nil, err
	}
	newEntry.ID = newID
	return newEntry, nil
}

type ScopeError struct{ Reason string }

func (e *ScopeError) Error() string { return "out of scope: " + e.Reason }

func itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

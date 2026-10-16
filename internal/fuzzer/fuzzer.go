package fuzzer

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jojin1709/agentburp/internal/db"
	"github.com/jojin1709/agentburp/internal/diff"
	"github.com/jojin1709/agentburp/internal/model"
	"github.com/jojin1709/agentburp/internal/scope"
)

// Options configures a fuzz run against a baseline request.
type Options struct {
	Param        string // header/query/body param name to fuzz (simple substitution mode)
	WordlistPath string
	NumRangeFrom int
	NumRangeTo   int
	OnlyAnomalies bool
	Workspace    string
	MaxRequests  int // hard safety cap
}

type ResultRow struct {
	Payload  string       `json:"payload"`
	EntryID  int64        `json:"entry_id"`
	Status   int          `json:"status"`
	Length   int          `json:"length"`
	Diff     *diff.Result `json:"diff,omitempty"`
	Anomaly  bool         `json:"anomaly"`
}

var httpClient = &http.Client{Timeout: 20 * time.Second}

// Run fuzzes entry `baselineID`'s request by substituting o.Param's value with
// each payload (from wordlist or numeric range), comparing every response
// against the untouched baseline response to flag anomalies.
func Run(d *db.DB, g *scope.Guard, baselineID int64, o Options) ([]ResultRow, error) {
	baseline, err := d.GetEntry(baselineID)
	if err != nil {
		return nil, err
	}
	if ok, reason := g.Allowed(baseline.Host); !ok {
		return nil, fmt.Errorf("out of scope: %s", reason)
	}
	if err := g.RequireActiveOK(true); err != nil { // caller (CLI) is responsible for --confirm gate
		return nil, err
	}

	payloads, err := loadPayloads(o)
	if err != nil {
		return nil, err
	}
	if o.MaxRequests > 0 && len(payloads) > o.MaxRequests {
		payloads = payloads[:o.MaxRequests]
	}

	var results []ResultRow
	for _, p := range payloads {
		g.Throttle()
		entry, err := sendWithParam(baseline, o.Param, p, o.Workspace)
		if err != nil {
			continue
		}
		id, err := d.InsertEntry(entry)
		if err != nil {
			continue
		}
		entry.ID = id
		dr := diff.Compare(baseline, entry)
		row := ResultRow{
			Payload: p,
			EntryID: id,
			Status:  entry.Status,
			Length:  entry.Length,
			Diff:    dr,
			Anomaly: !dr.Identical,
		}
		if !o.OnlyAnomalies || row.Anomaly {
			results = append(results, row)
		}
	}
	return results, nil
}

func loadPayloads(o Options) ([]string, error) {
	var out []string
	if o.WordlistPath != "" {
		f, err := os.Open(o.WordlistPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				out = append(out, line)
			}
		}
		return out, sc.Err()
	}
	if o.NumRangeTo > o.NumRangeFrom {
		for i := o.NumRangeFrom; i <= o.NumRangeTo; i++ {
			out = append(out, fmt.Sprintf("%d", i))
		}
		return out, nil
	}
	return nil, fmt.Errorf("no payload source: provide --wordlist or --range")
}

// sendWithParam does a crude substitution: replaces the param's value in the
// query string, else in a JSON/form body, else sets it as a header.
func sendWithParam(baseline *model.Entry, param, payload, workspace string) (*model.Entry, error) {
	url := baseline.URL
	body := baseline.ReqBody

	replaced := false
	if strings.Contains(url, param+"=") {
		url = replaceQueryParam(url, param, payload)
		replaced = true
	}
	if !replaced && body != "" && strings.Contains(body, "\""+param+"\"") {
		body = replaceJSONField(body, param, payload)
		replaced = true
	}

	req, err := http.NewRequest(baseline.Method, url, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}
	for k, v := range baseline.ReqHeaders {
		req.Header.Set(k, v)
	}
	if !replaced {
		req.Header.Set(param, payload) // fallback: fuzz as header
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

	return &model.Entry{
		Timestamp:   start,
		Method:      baseline.Method,
		URL:         url,
		Host:        baseline.Host,
		ReqHeaders:  baseline.ReqHeaders,
		ReqBody:     body,
		Status:      resp.StatusCode,
		RespHeaders: respHeaders,
		RespBody:    string(respBody),
		Length:      len(respBody),
		DurationMS:  time.Since(start).Milliseconds(),
		Workspace:   workspace,
		Tags:        []string{"fuzz", "param:" + param},
	}, nil
}

func replaceQueryParam(url, param, value string) string {
	idx := strings.Index(url, param+"=")
	if idx < 0 {
		return url
	}
	end := strings.IndexByte(url[idx:], '&')
	prefix := url[:idx] + param + "=" + value
	if end < 0 {
		return prefix
	}
	return prefix + url[idx+end:]
}

func replaceJSONField(body, field, value string) string {
	key := "\"" + field + "\""
	idx := strings.Index(body, key)
	if idx < 0 {
		return body
	}
	colon := strings.IndexByte(body[idx:], ':')
	if colon < 0 {
		return body
	}
	valStart := idx + colon + 1
	for valStart < len(body) && (body[valStart] == ' ') {
		valStart++
	}
	var valEnd int
	if valStart < len(body) && body[valStart] == '"' {
		valEnd = strings.IndexByte(body[valStart+1:], '"')
		if valEnd < 0 {
			return body
		}
		valEnd = valStart + 1 + valEnd + 1
		return body[:valStart] + "\"" + value + "\"" + body[valEnd:]
	}
	valEnd = strings.IndexAny(body[valStart:], ",}")
	if valEnd < 0 {
		return body
	}
	valEnd += valStart
	return body[:valStart] + value + body[valEnd:]
}

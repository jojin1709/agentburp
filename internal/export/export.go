package export

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jojin1709/agentburp/internal/model"
)

// ToCurl converts an HTTP entry to an executable, copy-pasteable cURL command.
func ToCurl(e *model.Entry) string {
	var parts []string
	parts = append(parts, "curl", "-s", "-i", "-X", e.Method)

	// Quote URL
	parts = append(parts, fmt.Sprintf("%q", e.URL))

	// Add Headers
	for k, v := range e.ReqHeaders {
		// Avoid hop-by-hop headers in curl replay
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Proxy-Connection") {
			continue
		}
		parts = append(parts, "-H", fmt.Sprintf("%q", fmt.Sprintf("%s: %s", k, v)))
	}

	// Add Body if present
	if e.ReqBody != "" {
		parts = append(parts, "--data-raw", fmt.Sprintf("%q", e.ReqBody))
	}

	return strings.Join(parts, " ")
}

// HAR 1.2 Data Structures
type HARLog struct {
	Log HAREntryLog `json:"log"`
}

type HAREntryLog struct {
	Version string     `json:"version"`
	Creator HARCreator `json:"creator"`
	Entries []HAREntry `json:"entries"`
}

type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HAREntry struct {
	StartedDateTime time.Time   `json:"startedDateTime"`
	Time            int64       `json:"time"`
	Request         HARRequest  `json:"request"`
	Response        HARResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         HARTimings  `json:"timings"`
}

type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []HARHeader `json:"headers"`
	QueryString []HARHeader `json:"queryString"`
	BodySize    int         `json:"bodySize"`
	PostData    *HARPost    `json:"postData,omitempty"`
}

type HARPost struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type HARResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []HARHeader `json:"headers"`
	Content     HARContent  `json:"content"`
	BodySize    int         `json:"bodySize"`
}

type HARContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type HARTimings struct {
	Send int `json:"send"`
	Wait int `json:"wait"`
	Receive int `json:"receive"`
}

// ToHAR converts a list of entries to valid standard HAR 1.2 JSON format.
func ToHAR(entries []*model.Entry) ([]byte, error) {
	har := HARLog{
		Log: HAREntryLog{
			Version: "1.2",
			Creator: HARCreator{
				Name:    "agentburp",
				Version: "0.1.3",
			},
			Entries: make([]HAREntry, 0, len(entries)),
		},
	}

	for _, e := range entries {
		var reqHeaders []HARHeader
		contentType := "application/octet-stream"
		for k, v := range e.ReqHeaders {
			reqHeaders = append(reqHeaders, HARHeader{Name: k, Value: v})
			if strings.EqualFold(k, "Content-Type") {
				contentType = v
			}
		}

		var respHeaders []HARHeader
		respContentType := "text/plain"
		for k, v := range e.RespHeaders {
			respHeaders = append(respHeaders, HARHeader{Name: k, Value: v})
			if strings.EqualFold(k, "Content-Type") {
				respContentType = v
			}
		}

		hEntry := HAREntry{
			StartedDateTime: e.Timestamp,
			Time:            e.DurationMS,
			Request: HARRequest{
				Method:      e.Method,
				URL:         e.URL,
				HTTPVersion: "HTTP/1.1",
				Headers:     reqHeaders,
				BodySize:    len(e.ReqBody),
			},
			Response: HARResponse{
				Status:      e.Status,
				StatusText:  "OK",
				HTTPVersion: "HTTP/1.1",
				Headers:     respHeaders,
				BodySize:    e.Length,
				Content: HARContent{
					Size:     e.Length,
					MimeType: respContentType,
					Text:     e.RespBody,
				},
			},
			Timings: HARTimings{
				Send:    0,
				Wait:    int(e.DurationMS),
				Receive: 0,
			},
		}

		if e.ReqBody != "" {
			hEntry.Request.PostData = &HARPost{
				MimeType: contentType,
				Text:     e.ReqBody,
			}
		}

		har.Log.Entries = append(har.Log.Entries, hEntry)
	}

	return json.MarshalIndent(har, "", "  ")
}

// FromHAR parses standard HAR 1.2 JSON and converts it into a slice of model.Entry objects.
func FromHAR(data []byte, workspace string) ([]*model.Entry, error) {
	var har HARLog
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("parse HAR json: %w", err)
	}

	var results []*model.Entry
	for _, item := range har.Log.Entries {
		reqHeaders := make(map[string]string)
		for _, h := range item.Request.Headers {
			reqHeaders[h.Name] = h.Value
		}

		respHeaders := make(map[string]string)
		for _, h := range item.Response.Headers {
			respHeaders[h.Name] = h.Value
		}

		reqBody := ""
		if item.Request.PostData != nil {
			reqBody = item.Request.PostData.Text
		}

		respBody := item.Response.Content.Text

		host := ""
		if u, err := url.Parse(item.Request.URL); err == nil {
			host = u.Host
		}
		if host == "" && reqHeaders["Host"] != "" {
			host = reqHeaders["Host"]
		}

		ts := item.StartedDateTime
		if ts.IsZero() {
			ts = time.Now()
		}

		length := item.Response.Content.Size
		if length == 0 {
			length = len(respBody)
		}

		e := &model.Entry{
			Timestamp:   ts,
			Method:      item.Request.Method,
			URL:         item.Request.URL,
			Host:        host,
			ReqHeaders:  reqHeaders,
			ReqBody:     reqBody,
			Status:      item.Response.Status,
			RespHeaders: respHeaders,
			RespBody:    respBody,
			Length:      length,
			DurationMS:  item.Time,
			Workspace:   workspace,
			Tags:        []string{"imported", "har"},
		}
		results = append(results, e)
	}
	return results, nil
}


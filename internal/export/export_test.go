package export

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jojin1709/agentburp/internal/model"
)

func TestToCurl(t *testing.T) {
	entry := &model.Entry{
		ID:     1,
		Method: "POST",
		URL:    "http://127.0.0.1:8080/api/login",
		ReqHeaders: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer testtoken",
			"Content-Length": "25",
		},
		ReqBody: `{"user":"admin","pass":"123"}`,
	}

	cmd := ToCurl(entry)
	if !strings.HasPrefix(cmd, "curl -s -i -X POST") {
		t.Fatalf("unexpected curl command prefix: %s", cmd)
	}
	if !strings.Contains(cmd, `"http://127.0.0.1:8080/api/login"`) {
		t.Fatalf("missing URL in curl: %s", cmd)
	}
	if !strings.Contains(cmd, `Authorization: Bearer testtoken`) {
		t.Fatalf("missing auth header in curl: %s", cmd)
	}
	if strings.Contains(cmd, `Content-Length`) {
		t.Fatalf("Content-Length should be omitted in curl command: %s", cmd)
	}
	if !strings.Contains(cmd, `--data-raw "{\"user\":\"admin\",\"pass\":\"123\"}"`) {
		t.Fatalf("missing or malformed body in curl: %s", cmd)
	}
}

func TestToHAR(t *testing.T) {
	entries := []*model.Entry{
		{
			ID:        1,
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       "http://127.0.0.1:8080/api/users",
			ReqHeaders: map[string]string{
				"Accept": "application/json",
			},
			Status: 200,
			RespHeaders: map[string]string{
				"Content-Type": "application/json",
			},
			RespBody:   `[{"id":1,"name":"Alice"}]`,
			Length:     26,
			DurationMS: 42,
		},
	}

	harBytes, err := ToHAR(entries)
	if err != nil {
		t.Fatalf("failed to convert to HAR: %v", err)
	}

	var har HARLog
	if err := json.Unmarshal(harBytes, &har); err != nil {
		t.Fatalf("HAR output is not valid JSON: %v\nOutput: %s", err, string(harBytes))
	}

	if har.Log.Version != "1.2" {
		t.Fatalf("expected HAR version 1.2, got %s", har.Log.Version)
	}
	if len(har.Log.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(har.Log.Entries))
	}
	e := har.Log.Entries[0]
	if e.Request.Method != "GET" || e.Request.URL != "http://127.0.0.1:8080/api/users" {
		t.Fatalf("unexpected request data: %+v", e.Request)
	}
	if e.Response.Status != 200 || e.Response.Content.Text != `[{"id":1,"name":"Alice"}]` {
		t.Fatalf("unexpected response data: %+v", e.Response)
	}
}

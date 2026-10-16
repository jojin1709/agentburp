package sitemap

import (
	"strings"
	"testing"

	"github.com/jojin1709/agentburp/internal/model"
)

func TestSitemapBuildAndRender(t *testing.T) {
	entries := []*model.Entry{
		{
			Host:   "api.target.com",
			Method: "GET",
			URL:    "http://api.target.com/v1/users?id=12&page=1",
			Status: 200,
		},
		{
			Host:       "api.target.com",
			Method:     "POST",
			URL:        "http://api.target.com/v1/users",
			ReqHeaders: map[string]string{"Content-Type": "application/json"},
			ReqBody:    `{"name":"Alice","role":"admin"}`,
			Status:     201,
		},
		{
			Host:   "api.target.com",
			Method: "GET",
			URL:    "http://api.target.com/v1/health",
			Status: 200,
		},
	}

	maps := Build(entries)
	if len(maps) != 1 {
		t.Fatalf("expected 1 host map, got %d", len(maps))
	}
	if maps[0].Host != "api.target.com" {
		t.Fatalf("expected host 'api.target.com', got %s", maps[0].Host)
	}
	if len(maps[0].Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(maps[0].Endpoints))
	}

	tree := RenderTree(maps)
	if !strings.Contains(tree, "api.target.com") {
		t.Errorf("tree missing host")
	}
	if !strings.Contains(tree, "/v1/users") || !strings.Contains(tree, "params: id, name, page, role") {
		t.Errorf("tree missing /v1/users or aggregated params: %s", tree)
	}
	if !strings.Contains(tree, "GET,POST") {
		t.Errorf("tree missing merged GET,POST methods: %s", tree)
	}
}

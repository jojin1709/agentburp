package report

import (
	"strings"
	"testing"

	"github.com/jojin1709/agentburp/internal/model"
)

func TestGenerateNuclei(t *testing.T) {
	finding := &model.Finding{
		Module:     "cors",
		Title:      "Overly Permissive CORS",
		Detail:     "Endpoint reflects origin without credential validation",
		Confidence: "high",
		EntryID:    42,
	}
	entry := &model.Entry{
		ID:     42,
		Method: "GET",
		URL:    "http://api.target.com/user",
		Host:   "api.target.com",
		ReqHeaders: map[string]string{
			"Origin": "https://evil.com",
		},
		Status: 200,
	}

	nucleiYAML := Generate(Nuclei, finding, entry)
	if !strings.Contains(nucleiYAML, "id: agentburp-cors-42") {
		t.Fatalf("Nuclei template missing ID: %s", nucleiYAML)
	}
	if !strings.Contains(nucleiYAML, "severity: high") {
		t.Fatalf("Nuclei template missing high severity: %s", nucleiYAML)
	}
	if !strings.Contains(nucleiYAML, "GET http://api.target.com/user HTTP/1.1") {
		t.Fatalf("Nuclei template missing raw HTTP line: %s", nucleiYAML)
	}
	if !strings.Contains(nucleiYAML, "Origin: https://evil.com") {
		t.Fatalf("Nuclei template missing Origin header: %s", nucleiYAML)
	}
	if !strings.Contains(nucleiYAML, "status:\n          - 200") {
		t.Fatalf("Nuclei template missing 200 status matcher: %s", nucleiYAML)
	}
}

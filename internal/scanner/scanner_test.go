package scanner

import (
	"testing"

	"github.com/jojin1709/agentburp/internal/model"
)

func TestScannerModules(t *testing.T) {
	// 1. Test GraphQL finding
	eGQL := &model.Entry{
		ID:       1,
		URL:      "https://example.com/api/graphql",
		RespBody: `{"data":{"__schema":{"types":[{"name":"User"}]}}}`,
	}
	findings := RunAll(eGQL)
	foundGQL := false
	for _, f := range findings {
		if f.Module == "graphql" {
			foundGQL = true
			if f.Confidence != "high" {
				t.Errorf("expected high confidence for introspection schema, got %s", f.Confidence)
			}
		}
	}
	if !foundGQL {
		t.Errorf("expected graphql finding")
	}

	// 2. Test JWT alg=none finding
	// eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
	jwtNone := "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9."
	eJWT := &model.Entry{
		ID:         2,
		URL:        "https://example.com/api/profile",
		ReqHeaders: map[string]string{"Authorization": jwtNone},
	}
	findingsJWT := RunAll(eJWT)
	foundJWTNone := false
	for _, f := range findingsJWT {
		if f.Module == "jwt" && f.Confidence == "high" {
			foundJWTNone = true
		}
	}
	if !foundJWTNone {
		t.Errorf("expected high confidence JWT alg=none finding")
	}

	// 3. Test Security Headers finding
	eSec := &model.Entry{
		ID:          3,
		URL:         "https://example.com/",
		Status:      200,
		RespHeaders: map[string]string{"Content-Type": "text/html; charset=utf-8"},
	}
	findingsSec := RunAll(eSec)
	foundCSP := false
	foundXCTO := false
	for _, f := range findingsSec {
		if f.Module == "security_headers" {
			if f.Title == "Missing Content-Security-Policy" {
				foundCSP = true
			}
			if f.Title == "Missing X-Content-Type-Options: nosniff" {
				foundXCTO = true
			}
		}
	}
	if !foundCSP || !foundXCTO {
		t.Errorf("expected security header findings (CSP=%v, XCTO=%v)", foundCSP, foundXCTO)
	}

	// 4. Test Sensitive Exposure
	eEnv := &model.Entry{
		ID:     4,
		URL:    "https://example.com/.env",
		Status: 200,
	}
	findingsEnv := RunAll(eEnv)
	foundEnv := false
	for _, f := range findingsEnv {
		if f.Module == "sensitive_exposure" && f.Confidence == "high" {
			foundEnv = true
		}
	}
	if !foundEnv {
		t.Errorf("expected high confidence .env exposure finding")
	}
}

package scope

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScopeLoadFeatures(t *testing.T) {
	yamlContent := `workspace: "test-workspace"
rate_limit_per_sec: 15.5
safe_mode: true
upstream_proxy: "http://127.0.0.1:8080"

allow_hosts:
  - "target.com"
  - "*.api.target.com"

deny_hosts:
  - "internal.target.com"

inject_headers:
  - "X-Bug-Bounty: researcher@intigriti.me"
  - "Authorization: Bearer secret-agent-token"

notify:
  webhook_url: "https://discord.com/api/webhooks/test"
  min_confidence: "high"
`

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "scope.yml")
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test scope.yml: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}

	if cfg.Workspace != "test-workspace" {
		t.Errorf("expected workspace 'test-workspace', got %q", cfg.Workspace)
	}
	if cfg.RateLimit != 15.5 {
		t.Errorf("expected rate limit 15.5, got %v", cfg.RateLimit)
	}
	if !cfg.SafeMode {
		t.Errorf("expected safe_mode true")
	}
	if cfg.UpstreamProxy != "http://127.0.0.1:8080" {
		t.Errorf("expected upstream_proxy 'http://127.0.0.1:8080', got %q", cfg.UpstreamProxy)
	}
	if len(cfg.AllowHosts) != 2 {
		t.Errorf("expected 2 allow_hosts, got %d", len(cfg.AllowHosts))
	}
	if len(cfg.DenyHosts) != 1 {
		t.Errorf("expected 1 deny_hosts, got %d", len(cfg.DenyHosts))
	}
	if len(cfg.InjectHeaders) != 2 {
		t.Fatalf("expected 2 inject_headers, got %d", len(cfg.InjectHeaders))
	}
	if cfg.InjectHeaders["X-Bug-Bounty"] != "researcher@intigriti.me" {
		t.Errorf("unexpected X-Bug-Bounty value: %q", cfg.InjectHeaders["X-Bug-Bounty"])
	}
	if cfg.InjectHeaders["Authorization"] != "Bearer secret-agent-token" {
		t.Errorf("unexpected Authorization value: %q", cfg.InjectHeaders["Authorization"])
	}
	if cfg.Notify.WebhookURL != "https://discord.com/api/webhooks/test" {
		t.Errorf("unexpected WebhookURL: %q", cfg.Notify.WebhookURL)
	}

	guard := NewGuard(cfg)
	if guard.Config() == nil {
		t.Fatal("expected guard.Config() to not be nil")
	}
	if guard.Config().UpstreamProxy != "http://127.0.0.1:8080" {
		t.Errorf("guard.Config().UpstreamProxy mismatch")
	}
}

package scope

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config is the scope.yml structure.
type Config struct {
	Workspace     string
	AllowHosts    []string
	DenyHosts     []string
	RateLimit     float64
	SafeMode      bool
	Notify        Notify
	UpstreamProxy string
	InjectHeaders map[string]string
}

type Notify struct {
	WebhookURL    string
	MinConfidence string
}

// Load reads a small, deliberately simple YAML-like config: flat
// "key: value" lines, "key:" followed by "  - item" list lines, and a
// one-level-deep "notify:" block. This avoids pulling in a YAML library
// (and the network fetch that requires) for a schema this small. If you
// need full YAML, swap this for gopkg.in/yaml.v3 once you can `go get` it.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	c := &Config{
		RateLimit:     10,
		InjectHeaders: make(map[string]string),
	}
	sc := bufio.NewScanner(f)

	var currentListKey string
	inNotify := false

	for sc.Scan() {
		raw := sc.Text()
		line := stripComment(raw)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))

		// list item
		if strings.HasPrefix(trimmed, "- ") {
			val := unquote(strings.TrimSpace(trimmed[2:]))
			switch currentListKey {
			case "allow_hosts":
				c.AllowHosts = append(c.AllowHosts, val)
			case "deny_hosts":
				c.DenyHosts = append(c.DenyHosts, val)
			case "inject_headers", "headers":
				if hparts := strings.SplitN(val, ":", 2); len(hparts) == 2 {
					c.InjectHeaders[strings.TrimSpace(hparts[0])] = strings.TrimSpace(hparts[1])
				}
			}
			continue
		}

		// key: value  OR  key:
		parts := strings.SplitN(trimmed, ":", 2)
		key := strings.TrimSpace(parts[0])
		val := ""
		if len(parts) > 1 {
			val = strings.TrimSpace(parts[1])
		}

		if indent == 0 {
			inNotify = false
			currentListKey = ""
		}

		switch {
		case key == "notify" && val == "":
			inNotify = true
			continue
		case inNotify && key == "webhook_url":
			c.Notify.WebhookURL = unquote(val)
			continue
		case inNotify && key == "min_confidence":
			c.Notify.MinConfidence = unquote(val)
			continue
		}

		if val == "" {
			// start of a list block
			currentListKey = key
			continue
		}
		currentListKey = ""

		switch key {
		case "workspace":
			c.Workspace = unquote(val)
		case "rate_limit_per_sec":
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				c.RateLimit = f
			}
		case "safe_mode":
			c.SafeMode = strings.EqualFold(val, "true")
		case "upstream_proxy", "upstream":
			c.UpstreamProxy = unquote(val)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if c.RateLimit <= 0 {
		c.RateLimit = 10
	}
	return c, nil
}

func stripComment(s string) string {
	inQuote := false
	for i, r := range s {
		if r == '"' {
			inQuote = !inQuote
		}
		if r == '#' && !inQuote {
			return s[:i]
		}
	}
	return s
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// hostMatch compares a scope pattern against a host, which may or may not
// carry a ":port" suffix. A pattern without a port matches that host on
// any port (so "target.com" covers "target.com:8443"); a pattern with an
// explicit port only matches that exact port.
func hostMatch(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)

	hostNoPort := host
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		hostNoPort = host[:i]
	}

	if strings.HasPrefix(pattern, "re:") {
		re, err := regexp.Compile(pattern[3:])
		if err == nil {
			return re.MatchString(host) || re.MatchString(hostNoPort)
		}
		return false
	}

	patternHasPort := strings.Count(pattern, ":") > 0 && !strings.HasPrefix(pattern, "*.")
	target := host
	if !patternHasPort {
		target = hostNoPort
	}

	if pattern == target {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".target.com"
		return strings.HasSuffix(target, suffix) || target == pattern[2:]
	}
	return false
}

// Guard enforces allow/deny lists and rate limiting. Safe for concurrent use.
type Guard struct {
	cfg      *Config
	mu       sync.Mutex
	lastReq  time.Time
	interval time.Duration
}

func NewGuard(cfg *Config) *Guard {
	g := &Guard{cfg: cfg}
	if cfg.RateLimit > 0 {
		g.interval = time.Duration(float64(time.Second) / cfg.RateLimit)
	}
	return g
}

func (g *Guard) Config() *Config {
	if g == nil {
		return nil
	}
	return g.cfg
}


func (g *Guard) Allowed(host string) (bool, string) {
	for _, d := range g.cfg.DenyHosts {
		if hostMatch(d, host) {
			return false, fmt.Sprintf("host %q matches deny rule %q", host, d)
		}
	}
	if len(g.cfg.AllowHosts) == 0 {
		return false, "no allow_hosts configured — refusing by default"
	}
	for _, a := range g.cfg.AllowHosts {
		if hostMatch(a, host) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("host %q not in allow_hosts", host)
}

func (g *Guard) Throttle() {
	if g.interval == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	wait := g.interval - time.Since(g.lastReq)
	if wait > 0 {
		time.Sleep(wait)
	}
	g.lastReq = time.Now()
}

func (g *Guard) RequireActiveOK(confirmed bool) error {
	if g.cfg.SafeMode && !confirmed {
		return fmt.Errorf("safe mode is on: active operation refused — rerun with --confirm to override")
	}
	return nil
}

---
name: agentburp
description: >-
  Drive the agentburp CLI and MCP server for HTTP proxy interception, traffic analysis,
  repeater testing, parameter fuzzing, response diffing, heuristic security scanning,
  and bug bounty PoC reporting.
---

# agentburp — AI Agent Operational Runbook

`agentburp` is a CLI-first, agent-native HTTP intercepting proxy and bug bounty toolkit written in Go, backed by SQLite, and featuring strict declarative YAML scope enforcement.

As an AI agent, you can drive `agentburp` either via the CLI (`agentburp <command>`) or over newline-delimited JSON-RPC stdio using `agentburp mcp-serve`.

---

## 1. Safety Rails & Scope Guard

> [!CRITICAL]
> **Never test targets outside `scope.yml`!**
> `agentburp` enforces in-kernel scope checking. If an HTTP request does not match `allow_hosts`, it is dropped with:
> `blocked by scope guard: host "<host>" not in allow_hosts`

### Verify Scope Before Any Test
```powershell
# View active scope rules
cat scope.yml
```

Sample safe `scope.yml`:
```yaml
workspace: default
allow_hosts:
  - "target.com"
  - "*.target.com"
deny_hosts:
  - "payments.target.com"
  - "admin.target.com"
rate_limit: 10
safe_mode: true
```

---

## 2. Core CLI Workflows

### A. Starting the Proxy Listener
```bash
# Standard local proxy
agentburp proxy start --addr 127.0.0.1:8888 --scope scope.yml

# Proxy chaining through upstream Burp Suite Pro / Caido
agentburp proxy start --addr 127.0.0.1:8888 --upstream http://127.0.0.1:8080

# Automatic bug bounty header injection
agentburp proxy start --inject-header "X-Bug-Bounty: researcher@platform" --inject-header "Authorization: Bearer token"
```
* Runs the intercepting proxy on port 8888. Full request and response bodies are captured into SQLite (`~/.agentburp/<workspace>.db`). All injected headers and upstream chained hops are preserved.

### B. Searching Traffic History
Search captured HTTP requests with structured JSON output:
```bash
# List last 20 requests
agentburp hist list --limit 20

# Filter by host
agentburp hist list --host target.com

# Filter by HTTP status code
agentburp hist list --status 403

# Filter by response body substring
agentburp hist list --body "admin"

# Show full details of a specific request/response ID
agentburp hist show 1
```

### C. Repeater (Request Replay & Header Tampering)
Replay captured requests with modified headers or bodies:
```bash
# Replay with modified Authorization header
agentburp repeat 1 --set "Authorization: Bearer attacker_token"

# Replay with new JSON payload
agentburp repeat 1 --body '{"user_id": 9999}'
```

### D. Parameter Fuzzing & IDOR Detection
Active fuzzing tests for anomalies in status code or response length:
```bash
# Numeric IDOR range fuzzing (requires --confirm when safe_mode is true)
agentburp fuzz 1 --param id --range-from 100 --range-to 120 --anomalies --confirm

# Wordlist fuzzing
agentburp fuzz 1 --param redirect --wordlist wordlists/open_redirect.txt --confirm
```

### E. Response Diffing
Compare two HTTP responses to highlight authorization bypasses:
```bash
# Compare Admin response (ID 1) with Low-Privilege response (ID 2)
agentburp diff 1 2
```

### F. Heuristic Vulnerability Scanner
Scan stored requests for common vulnerabilities (missing security headers, IDOR risks, CORS misconfigurations, sensitive tokens in URLs, reflected parameters):
```bash
agentburp scan 1
```

### G. Bug Bounty Report Generation
Generate submission-ready markdown reports:
```bash
# HackerOne format
agentburp report 1 --format hackerone

# Bugcrowd format
agentburp report 1 --format bugcrowd

# Generic markdown PoC
agentburp report 1 --format generic
```

### H. Workspace Management
Isolate bug bounty targets into distinct databases:
```bash
# Switch to or create a workspace
agentburp workspace use bugcrowd_target

# Check active workspace
agentburp workspace current
```

### I. Traffic Exporter (cURL & HAR 1.2)
Export captured requests to reproducible terminal commands or standard HTTP archives:
```bash
# Generate copy-pasteable cURL command for an entry
agentburp export 1 --format curl

# Generate standard HAR 1.2 for single entry
agentburp export 1 --format har

# Export entire workspace session to HAR file for Burp Suite or Caido
agentburp export --format har --out session.har --limit 500
```

### J. Traffic Importer (HAR 1.2)
Import sessions captured from Burp Suite, Caido, or browser DevTools:
```bash
# Import HAR into current workspace
agentburp import traffic.har

# Import into specific target workspace
agentburp import burp_export.har --workspace bugcrowd_target
```

### K. Target Site Map
Aggregate and view discovered attack surface endpoints and parameters:
```bash
# Render ASCII attack surface tree
agentburp map

# Filter by host
agentburp map --host api.target.com

# Machine-readable JSON output for AI agents
agentburp map --json
```

### L. Scope CLI Tester
Instantly check if a URL or host is authorized by scope.yml:
```bash
# Check single target
agentburp scope test https://api.target.com/v1/auth

# JSON output for agent automation
agentburp scope test evil.com --json
```

### M. HTTPS Root CA Generator
Generate and install local trusted CA for MITM TLS decryption:
```bash
# Generate ca.crt and ca.key
agentburp proxy ca
```

---

## 3. Native MCP Server (Model Context Protocol)

When interacting as an MCP client, start `agentburp` as an stdio server:
```bash
agentburp mcp-serve --scope scope.yml
```

### Supported MCP Methods:
1. `tools/list`: Returns available tools (`["history.search", "repeat", "fuzz", "diff", "scan"]`).
2. `history.search`: Search proxy database (`{"host": "target.com", "status": 200, "limit": 10}`).
3. `repeat`: Replay request (`{"id": 1, "set_headers": {"X-Custom": "test"}, "body": ""}`).
4. `fuzz`: Run parameter fuzzing (`{"baseline_id": 1, "param": "id", "range_from": 1, "range_to": 10, "only_anomalies": true}`).
5. `diff`: Diff two transaction records (`{"a": 1, "b": 2}`).
6. `scan`: Run heuristic security checks on an entry ID (`{"entry_id": 1}`).

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

### G. Bug Bounty & Vulnerability Report Generation
Generate submission-ready markdown and automated scan templates:
```bash
# HackerOne format
agentburp report 1 --format hackerone

# Bugcrowd format
agentburp report 1 --format bugcrowd

# Nuclei scanner YAML template
agentburp report 1 --format nuclei

# Generic markdown PoC
agentburp report 1 --format generic
```

### H. Raw HTTP Socket Replayer
Send un-canonicalized raw HTTP requests directly over TCP/TLS sockets (critical for HTTP request smuggling, header malformations, and zero-day testing):
```bash
# Replay raw request file over standard TCP
agentburp raw request.txt

# Replay over TLS with SNI
agentburp raw request.txt --ssl

# Override target socket host:port (useful for front-end/back-end smuggling)
agentburp raw request.txt --target backend.internal:8080
```

### I. Workspace Management
Isolate bug bounty targets into distinct databases:
```bash
# Switch to or create a workspace
agentburp workspace use bugcrowd_target

# Check active workspace
agentburp workspace current
```

### J. Traffic Exporter (cURL & HAR 1.2)
Export captured requests to reproducible terminal commands or standard HTTP archives:
```bash
# Generate copy-pasteable cURL command for an entry
agentburp export 1 --format curl

# Generate standard HAR 1.2 for single entry
agentburp export 1 --format har

# Export entire workspace session to HAR file for Burp Suite or Caido
agentburp export --format har --out session.har --limit 500
```

### K. Traffic Importer (HAR 1.2)
Import sessions captured from Burp Suite, Caido, or browser DevTools:
```bash
# Import HAR into current workspace
agentburp import traffic.har

# Import into specific target workspace
agentburp import burp_export.har --workspace bugcrowd_target
```

### L. Target Site Map
Aggregate and view discovered attack surface endpoints and parameters:
```bash
# Render ASCII attack surface tree
agentburp map

# Filter by host
agentburp map --host api.target.com

# Machine-readable JSON output for AI agents
agentburp map --json
```

### M. Scope CLI Tester & Match/Replace Rules
Instantly check if a URL or host is authorized by scope.yml:
```bash
# Check single target
agentburp scope test https://api.target.com/v1/auth

# JSON output for agent automation
agentburp scope test evil.com --json
```

#### Match & Replace Engine in `scope.yml`
Define automatic regex or substring rewriting rules for request headers, request bodies, response headers, or response bodies:
```yaml
match_replace:
  - type: request_header
    match: "User-Agent:.*"
    replace: "User-Agent: agentburp-agent/1.0"
  - type: request_body
    match: "re:\"debug\":\\s*false"
    replace: "\"debug\": true"
  - type: response_header
    match: "re:X-Frame-Options:.*"
    replace: ""
```

### N. HTTPS Root CA Generator
Generate and install local trusted CA for MITM TLS decryption:
```bash
# Generate ca.crt and ca.key
agentburp proxy ca
```

### O. Out-of-Band (OAST) Collaborator
Verify blind SSRF, blind XSS, and blind command injection callbacks:
```bash
# Start local collaborator receiver
agentburp oast start --addr 127.0.0.1:9998

# Generate a fresh correlation token and callback URL
agentburp oast token

# Poll for incoming callbacks matching a token
agentburp oast poll <token>

# List all received interactions
agentburp oast list
```

### P. WebSocket Interception & Frame Inspection
Inspect RFC 6455 WebSocket handshakes and frames (`ws://` and `wss://`):
```bash
# List captured WebSocket frames
agentburp ws list --limit 50

# Filter by HTTP upgrade handshake entry ID
agentburp ws list --entry-id 12

# Inspect full frame details
agentburp ws show 1
```

### Q. Embedded Web Dashboard
Launch the zero-dependency browser UI for visual inspection:
```bash
# Start standalone dashboard
agentburp ui --addr 127.0.0.1:8889

# Or run alongside the proxy
agentburp proxy start --addr 127.0.0.1:8888 --ui
```

---

## 3. Native MCP Server (Model Context Protocol)

When interacting as an MCP client, start `agentburp` as an stdio server:
```bash
agentburp mcp-serve --scope scope.yml
```

### Supported MCP Methods:
1. `tools/list`: Returns available tools (`history.search`, `repeat`, `fuzz`, `diff`, `scan`, `sitemap`, `export.curl`, `export.har`, `scope.test`, `report`, `oast.token`, `oast.poll`, `ws.list`).
2. `history.search`: Search proxy database (`{"host": "target.com", "status": 200, "limit": 10}`).
3. `repeat`: Replay request (`{"id": 1, "set_headers": {"X-Custom": "test"}, "body": ""}`).
4. `fuzz`: Run parameter fuzzing (`{"baseline_id": 1, "param": "id", "range_from": 1, "range_to": 10, "only_anomalies": true}`).
5. `diff`: Diff two transaction records (`{"a": 1, "b": 2}`).
6. `scan`: Run heuristic security checks on an entry ID (`{"entry_id": 1}`).
7. `sitemap`: Aggregate and retrieve attack surface tree (`{"host": "target.com", "limit": 100}`).
8. `export.curl`: Generate executable cURL command for an entry ID (`{"id": 1}`).
9. `export.har`: Export entry or session as HAR 1.2 JSON (`{"id": 1}`).
10. `scope.test`: Verify if a target URL/host is within declarative scope (`{"target": "https://api.target.com"}`).
11. `report`: Generate vulnerability report in HackerOne, Bugcrowd, Nuclei, or Generic format (`{"id": 1, "format": "nuclei"}`).
12. `oast.token`: Generate new OAST collaborator token and URL (`{}`).
13. `oast.poll`: Poll for incoming interactions on a token (`{"token": "c045d02a44ad9675"}`).
14. `ws.list`: List captured WebSocket frames (`{"entry_id": 12, "limit": 50}`).

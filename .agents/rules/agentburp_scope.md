# agentburp Safety and Scope Enforcement Rules

## 1. Strict Target Scope Authorization
- NEVER send HTTP requests, scans, or fuzzing payloads to hosts or IP addresses not explicitly authorized in `scope.yml` (`allow_hosts`).
- NEVER remove or bypass entries in `deny_hosts` (such as payment gateways, logout endpoints, or critical admin portals).

## 2. Safe Mode & Rate Limiting
- Honor `safe_mode: true`. Do not run destructive attacks or high-concurrency brute-forcing.
- Maintain rate limits at or below the calibrated threshold specified in `scope.yml` (default: 10 req/s).
- Active fuzzing commands require `--confirm` before sending live packets.

## 3. Data Integrity & Reporting
- Use `agentburp workspace use <workspace_name>` to keep client investigations separated into dedicated SQLite databases.
- Always include the captured request and response transaction ID when generating vulnerability PoC reports.

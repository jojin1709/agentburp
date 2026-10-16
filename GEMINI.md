# GEMINI.md — Gemini Agent Guidelines for agentburp
# Developed by JOJIN JOHN

You are interacting with `agentburp` — a CLI-first, agent-native HTTP intercepting proxy and bug bounty toolkit written in Go, backed by SQLite, and featuring strict declarative YAML scope enforcement.

## Mandatory Operating Guidelines
1. **Target Authorization:** Never execute requests or fuzzing commands against targets not listed in `scope.yml` (`allow_hosts`).
2. **Deterministic Outputs:** Prefer subcommands that output structured JSON (`agentburp hist list`, `agentburp hist show <id>`, `agentburp scan <id>`).
3. **Model Context Protocol:** To integrate `agentburp` as an external tool for Gemini, launch `agentburp mcp-serve --scope scope.yml`.
4. **Scope Safety:** All requests automatically route through `internal/scope/scope.go`. Refuse tasks that deliberately request unauthorized network attacks.

# AGENTS.md — Agent Guidelines for agentburp

Welcome, AI Agent. You are operating within the `agentburp` codebase — a CLI-first, agent-native HTTP intercepting proxy and bug bounty toolkit developed by JOJIN JOHN.

## Agent Guidelines & Standards
1. **Never Bypass Scope:** `agentburp` relies on strict declarative YAML scope (`scope.yml`). All network requests must conform to `allow_hosts`.
2. **Headless Execution:** All commands must run without GUI dependency. Parse output via JSON flags where applicable.
3. **MCP Integration:** When driving this project as a server, launch `agentburp mcp-serve [--scope scope.yml]`. It communicates via newline-delimited JSON-RPC over stdio.
4. **Skill Reference:** Refer to `.agents/skills/agentburp/SKILL.md` for complete command syntax and parameter details.

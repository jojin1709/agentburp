# Contributing to agentburp

First off, thank you for considering contributing to `agentburp`! 

`agentburp` was created and is actively developed by **[JOJIN JOHN](https://www.linkedin.com/in/jojin-john/)**. It is designed to be an agent-native, CLI-first, SQLite-backed HTTP intercepting proxy and bug bounty toolkit.

---

## Code of Conduct

This project and everyone participating in it is governed by the [agentburp Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## How Can I Contribute?

### 1. Reporting Bugs
- Check existing [GitHub Issues](https://github.com/jojin1709/agentburp/issues) to avoid duplicates.
- Provide a clear and descriptive title.
- Include the exact CLI command run, operating system, and expected vs actual behavior.

### 2. Suggesting Enhancements
- Explain why this enhancement would be useful to security researchers or autonomous AI agents.
- Describe the proposed CLI interface (flags, subcommands, or JSON-RPC methods).

### 3. Pull Requests
- Fork the repository and create your branch from `main`.
- If you've added code that should be tested, add unit tests.
- Ensure all tests pass (`go test ./...`).
- Verify formatting with `gofmt -s -w .`.

---

## Architectural Principles

1. **Strict Scope Safety:** Any network request must pass through `internal/scope/scope.go`. Never bypass `allow_hosts` or `deny_hosts`.
2. **Headless & Deterministic:** No GUI dependencies. Commands must support JSON output for agent parsing.
3. **Zero Bloat:** Rely on Go standard library and SQLite. Keep dependencies minimal and auditable.
4. **Decoupled Modules:** Internal packages (`proxy`, `repeater`, `fuzzer`, `diff`, `scanner`, `db`, `mcpserver`) should remain independently testable.

---

## Developer Contact

For security partnerships, feedback, or inquiries:
- **Developer:** [JOJIN JOHN](https://www.linkedin.com/in/jojin-john/)
- **GitHub:** [@jojin1709](https://github.com/jojin1709)

"""
agentburp Python Agent & LangChain Integration Toolkit
Developed by JOJIN JOHN

Use this module to connect agentburp to:
- LangChain / LangGraph
- CrewAI
- Microsoft AutoGen
- Ollama / Local Open Code LLMs
"""

import json
import subprocess
from typing import Optional, Dict, Any, List

class AgentBurpClient:
    """Wrapper around agentburp CLI and MCP stdio."""

    def __init__(self, binary_path: str = "agentburp", scope_path: str = "scope.yml"):
        self.binary_path = binary_path
        self.scope_path = scope_path

    def _run_cli(self, args: List[str]) -> str:
        cmd = [self.binary_path] + args + ["--scope", self.scope_path]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout.strip()

    def search_history(self, host: Optional[str] = None, status: Optional[int] = None, limit: int = 20) -> List[Dict[str, Any]]:
        """Search proxy history database."""
        args = ["hist", "list", "--limit", str(limit)]
        if host:
            args.extend(["--host", host])
        if status:
            args.extend(["--status", str(status)])
        out = self._run_cli(args)
        return json.loads(out) if out and out != "null" else []

    def get_entry(self, entry_id: int) -> Dict[str, Any]:
        """Fetch complete transaction details."""
        out = self._run_cli(["hist", "show", str(entry_id)])
        return json.loads(out)

    def replay_request(self, entry_id: int, headers: Optional[Dict[str, str]] = None, body: Optional[str] = None) -> Dict[str, Any]:
        """Replay request with optional header or body overrides."""
        args = ["repeat", str(entry_id)]
        if headers:
            for k, v in headers.items():
                args.extend(["--set", f"{k}: {v}"])
        if body:
            args.extend(["--body", body])
        out = self._run_cli(args)
        return json.loads(out)

    def scan_entry(self, entry_id: int) -> List[Dict[str, Any]]:
        """Run heuristic vulnerability scan on an entry."""
        out = self._run_cli(["scan", str(entry_id)])
        return json.loads(out) if out and out != "null" else []

    def diff_entries(self, id_a: int, id_b: int) -> Dict[str, Any]:
        """Compare two transaction responses."""
        out = self._run_cli(["diff", str(id_a), str(id_b)])
        return json.loads(out)

    def generate_report(self, entry_id: int, format_type: str = "hackerone") -> str:
        """Generate markdown bug bounty report."""
        return self._run_cli(["report", str(entry_id), "--format", format_type])


# LangChain Structured Tool Definitions
try:
    from langchain.tools import tool

    client = AgentBurpClient()

    @tool
    def search_http_history(host: Optional[str] = None, status: Optional[int] = None, limit: int = 10) -> str:
        """Search agentburp HTTP proxy history records."""
        return json.dumps(client.search_history(host=host, status=status, limit=limit), indent=2)

    @tool
    def repeat_http_request(entry_id: int, body: Optional[str] = None) -> str:
        """Replay an intercepted request through agentburp repeater."""
        return json.dumps(client.replay_request(entry_id, body=body), indent=2)

    @tool
    def scan_http_vulnerabilities(entry_id: int) -> str:
        """Run heuristic security checks on an HTTP transaction ID."""
        return json.dumps(client.scan_entry(entry_id), indent=2)

except ImportError:
    pass

if __name__ == "__main__":
    c = AgentBurpClient()
    print("agentburp Python Agent Toolkit initialized.")

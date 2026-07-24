from __future__ import annotations

import ipaddress
import json
import re
import socket
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEMO = {
    "request": {
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "fetch_url",
            "arguments": {"url": "http://169.254.169.254/latest/meta-data/iam", "output": "/tmp/report.json"},
        },
    },
    "policy": {
        "allowed_tools": ["fetch_url", "read_file"],
        "destructive_tools": ["delete_file", "run_shell"],
        "allowed_path_roots": ["/tmp/mcp-workspace"],
        "allow_private_networks": False,
        "require_approval_for_destructive": True,
    },
}

SECRET_PATTERN = re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*[^\s]+")


def _private_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        return "URL must use HTTP(S) with a hostname"
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        return "Production network targets must use HTTPS"
    try:
        addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(parsed.hostname, None)}
    except socket.gaierror:
        return "Hostname could not be resolved"
    if any(address.is_private or address.is_loopback or address.is_link_local or address.is_reserved for address in addresses):
        return "URL resolves to a private, loopback, link-local, or reserved address"
    return None


def _inside_roots(value: str, roots: list[str]) -> bool:
    path = Path(value).expanduser().resolve(strict=False)
    for root in roots:
        try:
            path.relative_to(Path(root).expanduser().resolve(strict=False))
            return True
        except ValueError:
            continue
    return False


def analyze(payload: dict[str, Any]) -> dict[str, Any]:
    request = payload.get("request", {})
    policy = payload.get("policy", {})
    if request.get("jsonrpc") != "2.0" or request.get("method") != "tools/call":
        raise ValueError("request must be an MCP JSON-RPC tools/call message")
    params = request.get("params", {})
    tool = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(tool, str) or not isinstance(arguments, dict):
        raise ValueError("tools/call requires a tool name and object arguments")
    violations = []

    def block(code: str, message: str, field: str = "") -> None:
        violations.append({"code": code, "field": field, "message": message})

    if tool not in policy.get("allowed_tools", []):
        block("tool_not_allowed", f"Tool {tool} is not in the allowlist", "params.name")
    destructive = tool in policy.get("destructive_tools", [])
    if destructive and policy.get("require_approval_for_destructive", True) and not payload.get("approved", False):
        block("approval_required", "Destructive tool call requires explicit approval", "approved")
    roots = [str(root) for root in policy.get("allowed_path_roots", [])]
    for key, value in arguments.items():
        if not isinstance(value, str):
            continue
        lower = key.lower()
        if lower in ("path", "file", "filename", "output", "directory") and roots and not _inside_roots(value, roots):
            block("path_outside_workspace", f"Path is outside configured roots: {value}", f"params.arguments.{key}")
        if lower in ("url", "uri", "endpoint") and not policy.get("allow_private_networks", False):
            reason = _private_url(value)
            if reason:
                block("network_target_blocked", reason, f"params.arguments.{key}")
        if SECRET_PATTERN.search(value):
            block("inline_secret", "Argument appears to contain an inline credential", f"params.arguments.{key}")
    return {
        "decision": "deny" if violations else "allow",
        "tool": tool,
        "destructive": destructive,
        "violation_count": len(violations),
        "violations": violations,
        "request_id": request.get("id"),
    }


class AuditStore:
    def __init__(self, path: str = ":memory:") -> None:
        self.connection = sqlite3.connect(path)
        self.connection.execute("CREATE TABLE IF NOT EXISTS decisions (id INTEGER PRIMARY KEY, tool TEXT, decision TEXT, payload TEXT)")

    def record(self, result: dict[str, Any]) -> int:
        cursor = self.connection.execute("INSERT INTO decisions(tool, decision, payload) VALUES(?,?,?)", (result["tool"], result["decision"], json.dumps(result, sort_keys=True)))
        self.connection.commit()
        return int(cursor.lastrowid)

    def count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM decisions").fetchone()[0])

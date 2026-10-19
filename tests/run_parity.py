"""Drive the browser/engine parity check.

Builds the case corpus, records what ``mcpinterlock.core.analyze`` decides for
each one, then hands both to ``tests/web_parity.mjs``, which runs the same
cases through the JavaScript the workbench ships and diffs the results.

Every case uses a literal IP address: the browser has no resolver, and the port
says so out loud instead of guessing, so hostname cases are not comparable and
are covered by ``test_core.py`` instead.

    python tests/run_parity.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcpinterlock.core import DEMO, analyze  # noqa: E402

BASE_POLICY = DEMO["policy"]


def call(tool, arguments, policy=None, approved=None, request_id=1):
    payload = {
        "request": {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        },
        "policy": policy or BASE_POLICY,
    }
    if approved is not None:
        payload["approved"] = approved
    return payload


def cases() -> list[dict]:
    open_net = dict(BASE_POLICY, allow_private_networks=True)
    no_approval = dict(BASE_POLICY, require_approval_for_destructive=False)
    return [
        DEMO,
        call("fetch_url", {"url": "https://93.184.216.34/ok", "output": "/tmp/mcp-workspace/out.json"}),
        call("fetch_url", {"url": "http://93.184.216.34/ok"}),
        call("fetch_url", {"url": "http://127.0.0.1:8080/health"}),
        call("fetch_url", {"url": "https://10.0.0.5/internal"}),
        call("fetch_url", {"url": "https://172.16.4.1/internal"}),
        call("fetch_url", {"url": "https://192.168.1.1/router"}),
        call("fetch_url", {"url": "https://100.64.0.1/cgnat"}),
        call("fetch_url", {"url": "https://224.0.0.1/multicast"}),
        call("fetch_url", {"url": "https://[::1]/loopback"}),
        call("fetch_url", {"url": "https://[fd00::1]/ula"}),
        call("fetch_url", {"url": "ftp://93.184.216.34/file"}),
        call("fetch_url", {"url": "not a url"}),
        call("fetch_url", {"url": "https://93.184.216.34/ok"}, policy=open_net),
        call("read_file", {"path": "/tmp/mcp-workspace/notes.txt"}),
        call("read_file", {"path": "/tmp/mcp-workspace/../../etc/passwd"}),
        call("read_file", {"path": "/etc/passwd"}),
        call("read_file", {"filename": "/tmp/mcp-workspace/sub/dir/a.txt"}),
        call("delete_file", {"path": "/tmp/mcp-workspace/old.txt"}),
        call("delete_file", {"path": "/tmp/mcp-workspace/old.txt"}, approved=True),
        call("delete_file", {"path": "/tmp/mcp-workspace/old.txt"}, policy=no_approval),
        call("run_shell", {"command": "ls", "path": "/tmp/mcp-workspace"}),
        call("read_file", {"path": "/tmp/mcp-workspace/a.txt", "note": "api_key=sk-live-123"}),
        call("read_file", {"path": "/tmp/mcp-workspace/a.txt", "note": "Authorization token: abc123"}),
        call("read_file", {"path": "/tmp/mcp-workspace/a.txt", "count": 3}),
        call("unknown_tool", {"path": "/tmp/mcp-workspace/a.txt"}),
        {"request": {"jsonrpc": "2.0", "id": 9, "method": "resources/read", "params": {}}, "policy": BASE_POLICY},
        {"request": {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": 7, "arguments": {}}}, "policy": BASE_POLICY},
    ]


def main() -> int:
    payloads = cases()
    expected = []
    for payload in payloads:
        try:
            expected.append(analyze(payload))
        except ValueError as error:
            expected.append({"error": str(error)})

    with tempfile.TemporaryDirectory() as tmp:
        cases_path = Path(tmp) / "cases.json"
        expected_path = Path(tmp) / "expected.json"
        cases_path.write_text(json.dumps(payloads))
        expected_path.write_text(json.dumps(expected))
        script = Path(__file__).resolve().parent / "web_parity.mjs"
        result = subprocess.run(["node", str(script), str(cases_path), str(expected_path)])
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import DEMO, analyze
from .server import serve


def main() -> None:
    parser = argparse.ArgumentParser(prog="mcpinterlock")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze_cmd = sub.add_parser("analyze")
    analyze_cmd.add_argument("input")
    sub.add_parser("demo")
    server = sub.add_parser("serve")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    if args.command == "serve":
        serve(args.host, args.port)
        return
    payload = DEMO if args.command == "demo" else json.loads(Path(args.input).read_text())
    print(json.dumps(analyze(payload), indent=2))

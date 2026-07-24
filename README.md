# mcpinterlock

**Policy firewall and audit layer for MCP tool calls.**

![mcpinterlock cover](demo/cover.png)

Enforce tool allowlists, path boundaries, destructive approvals, secret checks, and SSRF controls.

![mcpinterlock workbench](demo/dashboard.png)

## What ships

- A deterministic domain analysis engine with explicit scope
- JSON API and responsive local browser workbench
- CLI demo and file-driven analysis
- Docker image, unit tests, and GitHub Actions matrix
- No API keys and no uploaded user data

## Run it end to end

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -e .
mcpinterlock demo
mcpinterlock serve
```

Open <http://127.0.0.1:8090>. Analyze your own JSON input with `mcpinterlock analyze input.json`.

## API

- `GET /api/demo` returns the committed fixture and result.
- `POST /api/analyze` runs the same engine on a JSON body.

## Current basis

- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)

## Demo result

One `fetch_url` call is denied for two independent reasons: it targets cloud instance metadata over an unsafe network path and writes outside the configured workspace. A separate test permits an allowlisted read inside the root and records the decision in SQLite.

## Scope

The engine is a pre-execution policy layer, not an OAuth implementation or OS sandbox. Production MCP systems still need audience-validated tokens, per-client consent, egress enforcement, and process isolation.

## Test

```bash
python -m unittest discover -s tests -v
```

MIT licensed.

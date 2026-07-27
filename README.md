# mcpinterlock

**An agent with a `fetch_url` tool is one crafted request away from reading your cloud credentials.**

![mcpinterlock cover](demo/cover.png)

`169.254.169.254` is the link-local address every major cloud uses to serve instance metadata — including, if nobody's stopped it, IAM credentials. Give an MCP agent an unrestricted `fetch_url` tool and a prompt injection that asks it to "check this URL" is an SSRF attack away from exfiltrating them. mcpinterlock sits in front of every tool call and actually resolves the hostname before deciding whether the request is safe, instead of trusting the URL string.

![mcpinterlock workbench](demo/dashboard.png)

## How it works

Every tool call is checked against an explicit policy before it runs: is the tool on the allowlist, does a destructive tool have approval, does a file path stay inside the configured workspace root, does the request contain something that looks like a live secret. The network check is the one that actually matters — it resolves the hostname via DNS and rejects the request if any resolved address is private, loopback, link-local, or otherwise reserved, which is what stops the metadata-endpoint attack a naive "does the URL look okay" string check would miss entirely.

## What ships

- Real DNS resolution and private/loopback/link-local/reserved IP rejection, not string matching on the URL
- Tool allowlisting, destructive-action approval gating, and path-boundary enforcement
- Live secret-pattern detection in call arguments
- Every decision logged to SQLite with the specific violation codes that fired
- CLI, JSON API, browser workbench, Docker, tests, and CI

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

## The result

A `fetch_url` call targeting the AWS/GCP/Azure metadata address is denied for two independent reasons at once: the resolved address is link-local, and the requested output path falls outside the configured workspace root. A second test runs an allowlisted read inside the root, confirms it's permitted, and checks the decision landed in SQLite — so "why did it allow this one" has an actual answer.

## Scope

This is a pre-execution policy layer that mediates the calls presented to it, not an OAuth implementation or an OS-level sandbox. Production MCP deployments still need audience-validated tokens, per-client consent flows, egress network controls, and a server implementation that can't be talked out of calling this layer in the first place.

## Test

```bash
python -m unittest discover -s tests -v
```

## Research basis

- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)

MIT licensed.

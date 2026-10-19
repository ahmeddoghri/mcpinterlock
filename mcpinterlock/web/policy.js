(function (root) {
// A port of mcpinterlock/core.py's analyze(), so the workbench decides in the
// browser instead of posting the tool call to a server. Nothing leaves the page.
//
// One deliberate difference, because a browser has no resolver: core.py calls
// getaddrinfo() to catch a hostname that points at a private address. Here a
// literal IP is checked exactly as Python checks it, and a hostname that is not
// a literal IP is reported as unresolved rather than quietly allowed.
// tests/web_parity.mjs pins the agreement on literal addresses.

const SECRET_PATTERN = /(api[_-]?key|token|secret|password)\s*[=:]\s*[^\s]+/i;

function parseIPv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const bytes = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const v = Number(part);
    if (v > 255) return null;
    bytes.push(v);
  }
  return bytes;
}

// Mirrors Python's ipaddress: "not globally routable unicast, or multicast".
function isBlockedV4(b) {
  const [a, c] = b;
  if (a === 0) return true;                                  // this network
  if (a === 10) return true;                                 // private
  if (a === 127) return true;                                // loopback
  if (a === 169 && c === 254) return true;                   // link-local
  if (a === 172 && c >= 16 && c <= 31) return true;          // private
  if (a === 192 && c === 168) return true;                   // private
  if (a === 192 && c === 0 && b[2] === 0) return true;       // IETF protocol assignments
  if (a === 192 && c === 0 && b[2] === 2) return true;       // documentation
  if (a === 198 && (c === 18 || c === 19)) return true;      // benchmarking
  if (a === 198 && c === 51 && b[2] === 100) return true;    // documentation
  if (a === 203 && c === 0 && b[2] === 113) return true;     // documentation
  if (a === 100 && c >= 64 && c <= 127) return true;         // RFC 6598 carrier-grade NAT
  if (a >= 224 && a <= 239) return true;                     // multicast
  if (a >= 240) return true;                                 // reserved / broadcast
  return false;
}

function isBlockedV6(host) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "::1" || h === "::") return true;
  if (/^f[cd]/.test(h)) return true;   // unique local
  if (/^fe[89ab]/.test(h)) return true; // link-local
  if (/^ff/.test(h)) return true;       // multicast
  return false;
}

function privateUrlReasons(url) {
  const reasons = [];
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return ["URL must use HTTP(S) with a hostname"];
  }
  const scheme = parsed.protocol.replace(":", "");
  if ((scheme !== "https" && scheme !== "http") || !parsed.hostname) {
    return ["URL must use HTTP(S) with a hostname"];
  }
  const host = parsed.hostname;
  if (scheme === "http" && !["localhost", "127.0.0.1", "[::1]", "::1"].includes(host)) {
    reasons.push("Production network targets must use HTTPS");
  }
  const v4 = parseIPv4(host.replace(/^\[|\]$/g, ""));
  const literal = v4 !== null || host.includes(":") || /^\[.*\]$/.test(host);
  if (!literal) {
    reasons.push("Hostname could not be resolved in the browser; the CLI resolves it");
    return reasons;
  }
  if (v4 ? isBlockedV4(v4) : isBlockedV6(host)) {
    reasons.push("URL resolves to a non-public or multicast address");
  }
  return reasons;
}

// Python resolves the path before comparing; without a filesystem we normalize
// the same way a POSIX resolve would, minus symlinks.
function normalize(value) {
  const absolute = value.startsWith("/");
  const out = [];
  for (const part of value.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") out.pop();
    else out.push(part);
  }
  return (absolute ? "/" : "") + out.join("/");
}

function insideRoots(value, roots) {
  const path = normalize(value);
  return roots.some((root) => {
    const r = normalize(String(root));
    return path === r || path.startsWith(r.endsWith("/") ? r : r + "/");
  });
}

function analyze(payload) {
  const request = payload.request || {};
  const policy = payload.policy || {};
  if (request.jsonrpc !== "2.0" || request.method !== "tools/call") {
    throw new Error("request must be an MCP JSON-RPC tools/call message");
  }
  const params = request.params || {};
  const tool = params.name;
  const args = params.arguments;
  if (typeof tool !== "string" || typeof args !== "object" || args === null || Array.isArray(args)) {
    throw new Error("tools/call requires a tool name and object arguments");
  }
  const violations = [];
  const block = (code, message, field = "") => violations.push({ code, field, message });

  if (!(policy.allowed_tools || []).includes(tool)) {
    block("tool_not_allowed", `Tool ${tool} is not in the allowlist`, "params.name");
  }
  const destructive = (policy.destructive_tools || []).includes(tool);
  const needsApproval = policy.require_approval_for_destructive !== false;
  if (destructive && needsApproval && !payload.approved) {
    block("approval_required", "Destructive tool call requires explicit approval", "approved");
  }
  const roots = (policy.allowed_path_roots || []).map(String);
  for (const [key, value] of Object.entries(args)) {
    if (typeof value !== "string") continue;
    const lower = key.toLowerCase();
    if (["path", "file", "filename", "output", "directory"].includes(lower) && roots.length && !insideRoots(value, roots)) {
      block("path_outside_workspace", `Path is outside configured roots: ${value}`, `params.arguments.${key}`);
    }
    if (["url", "uri", "endpoint"].includes(lower) && !policy.allow_private_networks) {
      for (const reason of privateUrlReasons(value)) block("network_target_blocked", reason, `params.arguments.${key}`);
    }
    if (SECRET_PATTERN.test(value)) {
      block("inline_secret", "Argument appears to contain an inline credential", `params.arguments.${key}`);
    }
  }
  return {
    decision: violations.length ? "deny" : "allow",
    tool,
    destructive,
    violation_count: violations.length,
    violations,
    request_id: request.id === undefined ? null : request.id,
  };
}

const DEMO = {
  request: {
    jsonrpc: "2.0",
    id: 42,
    method: "tools/call",
    params: {
      name: "fetch_url",
      arguments: { url: "http://169.254.169.254/latest/meta-data/iam", output: "/tmp/report.json" },
    },
  },
  policy: {
    allowed_tools: ["fetch_url", "read_file"],
    destructive_tools: ["delete_file", "run_shell"],
    allowed_path_roots: ["/tmp/mcp-workspace"],
    allow_private_networks: false,
    require_approval_for_destructive: true,
  },
};

const api = { analyze, DEMO };
if (typeof module !== "undefined" && module.exports) module.exports = api;
else root.INTERLOCK = api;
})(this);

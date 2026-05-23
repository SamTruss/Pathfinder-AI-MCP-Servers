# MCP servers

This directory contains the MCP (Model Context Protocol) servers that
Pathfinder uses to invoke external tools safely.

Each MCP server is a small, standalone Python process that:

1. Exposes a fixed set of named, structured tools to the agent
2. Translates each tool call into a controlled invocation of the
   underlying binary or service
3. Enforces safety constraints (argument allowlists, target restrictions,
   timeouts) at the boundary between the agent and the tool
4. Returns structured results suitable for parsing by `MCPActor`

## Why MCP servers live here, not in `pathfinder/`

The `pathfinder/` package is library code: classes, types, control loop.
MCP servers are independent processes — they have their own lifetimes,
their own dependencies (often a CLI binary like `nmap`), and they can in
principle be reused outside Pathfinder. Putting them in `scripts/`
keeps the package boundary clean.

## Why we write our own MCP servers

The governance claim of this framework rests on **concrete enforcement**
of safety constraints, not declared ones. A third-party MCP server that
forwards arbitrary arguments to its underlying tool gives no auditable
guarantee that destructive operations cannot reach the binary. Our own
servers can.

In each server file, the safety constraints are:

- **Visible** — implemented as plain Python in the same file as the
  tool dispatch, not configuration buried elsewhere
- **Auditable** — readable in under 200 lines per server, with the
  allowlist sets defined as named constants
- **Testable** — every safety claim has a corresponding unit test that
  attempts to violate it and asserts the violation is rejected

Quoted text in the thesis describing what an MCP server does or does
not allow must match the code in the file. If the code changes, the
thesis text changes.

## Available servers

### `nmap_mcp_server.py`

Wraps the `nmap` CLI to provide network-scan capabilities under a
strict allowlist.

**Exposed tools (named operations, structured arguments only):**

- `nmap_discover` — host discovery (ping sweep) over a target range
- `nmap_port_scan` — TCP connect scan of specified ports on a target
- `nmap_version_scan` — service version detection on specified ports

**Argument constraints:**

- Targets must be valid hosts, IP addresses, or CIDR ranges
- Ports must be valid port specifications (`80`, `1-1000`, `22,80,443`)
- Optional target allowlist (default: off; controlled by `--target-allowlist`)
- Optional per-call timeout (default: 60 seconds)
- No raw argument passthrough — the agent cannot pass arbitrary nmap flags

**Underlying binary:** `nmap` CLI must be on the system PATH. Tested
against Nmap 7.94+. The server does not bundle nmap; it shells out to
the local binary.

**What this server cannot do:**

- Run NSE scripts (`--script`)
- Perform OS detection (`-O`) — root/admin required, intentionally omitted
- Perform UDP scans (`-sU`) — root/admin required, intentionally omitted
- Perform raw-packet scans (`-sS`, `-sN`, etc.) — root/admin required,
  intentionally omitted
- Take arbitrary nmap flags

If a future capability requires one of these, it is added as a new
named operation with its own constraints, not as a passthrough.

### `http_auth_mcp_server.py`

Tests HTTP authentication against in-scope web services. Used to
validate default-credential vulnerabilities on PLC web UIs and the
Scada-LTS HMI in the testbed.

**Exposed tools:**

- `http_form_login` — POST a username/password to a login form endpoint
- `http_basic_auth` — make an HTTP request with Basic Auth credentials

**Argument constraints:**

- URL scheme must be `http` or `https`; other schemes rejected
- Credential strings are bounded in length to prevent abuse
- Returns structured success/failure signals only — status code,
  response size, cookies set, redirect target. Never returns the
  response body, so the agent cannot scrape arbitrary site content
  through this tool.
- Optional `verify_tls=false` for lab self-signed certs; off by default

**What this server cannot do:**

- Submit forms to URLs outside the engagement scope (when scope
  enforcement is enabled in `ScopedPolicy`)
- Return full response bodies
- Follow arbitrary redirect chains; redirect target is reported but
  not auto-followed beyond a single hop

### `modbus_mcp_server.py`

Read-only Modbus TCP client. Used to enumerate PLC state without any
risk of altering it.

**Exposed tools (all read-only):**

- `modbus_read_coils` (FC1)
- `modbus_read_discrete_inputs` (FC2)
- `modbus_read_holding_registers` (FC3)
- `modbus_read_input_registers` (FC4)

**Argument constraints:**

- `address`, `count`, `unit_id`, `port`, and `timeout_seconds`
  validated against Modbus protocol bounds
- Read-only **by construction** — no Modbus write functions
  (`write_coil`, `write_register`, `write_coils`, `write_registers`)
  are imported, aliased, or called anywhere in the server file
- A file-level test (`test_server_file_contains_no_modbus_write_calls`)
  greps the source for write function names; if any are ever added,
  the test fails immediately

**What this server cannot do:**

- Write any Modbus value, ever. This is enforced structurally, not
  by runtime check. To verify by inspection:
  `grep -E 'write_coil|write_register|write_coils|write_registers'
  scripts/mcp_servers/modbus_mcp_server.py` returns no matches.

### `report_mcp_server.py`

Records structured vulnerability findings during the Report phase.
Each finding is validated against a strict schema before being written
to the findings audit log.

**Exposed tools:**

- `draft_finding` — primary name; what the LLM naturally chooses
- `write_finding` — alias with identical schema

**Argument constraints (schema-validated):**

- `title` (string, ≤200 chars)
- `description` (string, ≤2000 chars)
- `evidence` (non-empty list of strings)
- `severity` (string, typically with embedded CVSS, e.g. `"High (CVSS v3.1: 8.2)"`)
- `affected_assets` (non-empty list of strings)
- `remediation_guidance` (non-empty list of strings)
- `standards_mapping` (non-empty list of strings; CWE entries must
  match `CWE-NNNN`; non-CWE entries like NIST CSF or ISO refs allowed)
- `vulnerability_id` (optional integer)

All findings are appended one-per-line to `runs/findings/findings.jsonl`
with a generated UUID and timestamp.

**What this server cannot do:**

- Accept findings missing any required field
- Accept free-form prose in place of structured fields — the server
  is the enforcement boundary; the agent cannot bypass the schema

### `cve_mcp_server.py`

Looks up real CVE records from the NIST National Vulnerability
Database (NVD) so findings can cite authoritative sources rather than
LLM-fabricated severity scores.

**Exposed tools:**

- `cve_search` — keyword search (e.g. `"Werkzeug 0.16.0"`); returns
  up to `max_results` compact CVE records sorted by CVSS severity
- `cve_lookup` — exact CVE ID lookup (e.g. `"CVE-2023-46136"`)

**Argument constraints:**

- `keyword` must be 3–100 characters
- `max_results` capped at 10
- `cve_id` must match `CVE-YYYY-NNNN+`
- Returns a compact view: `cve_id`, `title`, `description` (capped at
  500 chars), `cvss_v3_score`, `cvss_v3_severity`, `cvss_v3_vector`,
  `cwe_ids`, `published_date`, `last_modified`, `references` (up to 3)

**External service:** Queries the NVD CVE API 2.0
(`https://services.nvd.nist.gov/rest/json/cves/2.0`). Picks up an
optional `NVD_API_KEY` environment variable; without one, NVD
rate-limits unauthenticated callers to ~5 requests per 30 seconds.

**What this server cannot do:**

- Return raw NVD JSON — the compact view is intentional, both to
  keep agent prompt tokens reasonable and to constrain the surface
- Make non-NVD queries

## Running a server manually

For development, debugging, or inspection.

### With the MCP inspector (recommended)

The `mcp` Python SDK ships with an inspector that runs an interactive
UI for any MCP server:

```bash
uv run mcp dev scripts/mcp_servers/nmap_mcp_server.py
```

This lets you see the server's tool list, invoke tools with arbitrary
arguments, and read the structured responses without any Pathfinder
code involved. Swap in any server file: `report_mcp_server.py`,
`cve_mcp_server.py`, etc.

### As a stdio subprocess

You can also speak the protocol directly. This is what Pathfinder's
`MCPActor` does internally:

```bash
uv run python scripts/mcp_servers/nmap_mcp_server.py
```

The server reads JSON-RPC messages on stdin and writes responses on
stdout. Useful when debugging transport-level issues.

## Adding a new MCP server

1. Create `<name>_mcp_server.py` in this directory
2. Use the `mcp.server.fastmcp.FastMCP` framework (the same pattern as
   `nmap_mcp_server.py`)
3. Declare each tool with `@mcp.tool()` and explicit type-annotated
   arguments — these become the JSON schema MCP clients consume
4. Implement argument validation as private helper functions; reject
   invalid input with a clear error message
5. Document each tool's safety constraints in the docstring
6. Add an entry to this README under "Available servers"
7. Add tests under `tests/scripts/` mirroring the path

The server should be small (target: under 200 lines) and should resist
the urge to add capabilities the agent doesn't yet need. Each capability
is a potential safety surface; "if it isn't there, it can't be misused."

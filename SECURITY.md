# Security Policy

## Scope

This repository contains MCP server implementations for security tooling. While these servers are designed for **authorised security assessment** within controlled environments, security vulnerabilities in the server code itself could have downstream impact.

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | ✅ Current |

## Reporting a Vulnerability

If you discover a security vulnerability in any MCP server in this repository, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **[security contact — update with your preferred email]**

Include:
- A description of the vulnerability
- Steps to reproduce
- The affected server(s) and version/commit
- Any potential impact assessment

### Response Timeline

- **Acknowledgement:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix or mitigation:** Dependent on severity, targeting 30 days for critical issues

## Responsible Use

These MCP servers provide interfaces to security assessment tools (network scanners, protocol analysers, etc.). They are intended **exclusively** for:

- Authorised penetration testing engagements
- Security research in controlled lab environments
- Academic research with appropriate ethical approval

**Unauthorised use of these tools against systems you do not own or have explicit permission to test is illegal and unethical.** The authors accept no liability for misuse.

## Security Design Principles

All MCP servers in this repository follow these principles:

1. **Least privilege** — Servers request only the permissions required for their specific function
2. **Input validation** — All tool inputs are validated before execution
3. **No credential storage** — Servers do not persist credentials; authentication is handled externally
4. **Audit logging** — Tool invocations are logged for traceability
5. **Scoped execution** — Servers are designed to operate within defined target boundaries

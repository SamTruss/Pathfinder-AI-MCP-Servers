"""Nmap MCP server.

A standalone MCP server that exposes named, structured nmap operations to
agentic clients. The server intentionally does NOT support raw argument
passthrough; every nmap invocation is constructed from a closed set of
named operations defined in this file.

Safety model:

* Three named tools: ``nmap_discover``, ``nmap_port_scan``,
  ``nmap_version_scan``. The agent picks a tool by name; arguments are
  structured and validated.
* Targets must parse as a hostname, IP address, or CIDR range.
* Ports must parse as a valid port specification (single port, range,
  or comma-separated list).
* Optional target allowlist (off by default; configured at server
  startup via ``--target-allowlist``).
* Per-call timeout (default 60 seconds; configurable per-call up to a
  hard ceiling of 300 seconds).
* No NSE scripts, no OS detection, no UDP/SYN/raw-packet scans. These
  intentionally cannot be invoked through this server.

Underlying binary: ``nmap`` must be on the system PATH. Tested against
Nmap 7.94 and later.

Run standalone for inspection:

.. code-block:: bash

    uv run mcp dev scripts/mcp_servers/nmap_mcp_server.py

Run as stdio subprocess (what MCPActor does):

.. code-block:: bash

    uv run python scripts/mcp_servers/nmap_mcp_server.py
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import re
import shutil
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

_log = logging.getLogger("nmap_mcp_server")

# ---- Constants -------------------------------------------------------------

# Hard ceiling on per-call timeout. Even if the caller asks for longer,
# this is the maximum the server will honour.
_MAX_TIMEOUT_SECONDS = 300

# Default per-call timeout if the caller does not specify one.
_DEFAULT_TIMEOUT_SECONDS = 60

# Valid TCP/UDP port range.
_MIN_PORT = 1
_MAX_PORT = 65535

# Pattern for a valid hostname. Conservative: alphanumerics, dots, hyphens.
_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

# Pattern for a valid port specification. Examples that pass:
#   "80", "1-1000", "22,80,443", "1-1000,8080,8443"
_PORT_SPEC_PATTERN = re.compile(
    r"^(\d+(-\d+)?)(,\d+(-\d+)?)*$"
)


# ---- Server configuration --------------------------------------------------


@dataclass
class ServerConfig:
    """Runtime configuration applied at server startup.

    Attributes:
        target_allowlist: Optional list of hosts/CIDRs that are the only
            permitted targets. If empty, no server-side target check is
            applied (Pathfinder's Policy layer becomes the source of
            truth for target scope).
        nmap_path: Resolved absolute path to the nmap binary.
    """

    target_allowlist: list[str] = field(default_factory=list)
    nmap_path: str = "nmap"


# Module-level config; populated by main(). Tools read this at call time.
_CONFIG = ServerConfig()


# ---- Validation helpers ----------------------------------------------------


def _validate_target(target: str) -> str:
    """Validate that ``target`` is a hostname, IP address, or CIDR range.

    Returns the (stripped) target unchanged if valid.

    Raises:
        ValueError: If the target does not parse as any accepted form.
    """
    target = target.strip()
    if not target:
        msg = "target must not be empty"
        raise ValueError(msg)

    # Try as IP address (v4 or v6)
    try:
        ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        return target

    # Try as CIDR network
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        pass
    else:
        return target

    # Reject anything that looks numeric (dotted digits) but isn't a
    # valid IP. "256.256.256.256" matches the hostname regex below
    # but is clearly not what was intended.
    if re.match(r"^\d+(\.\d+)*$", target):
        msg = (
            f"target '{target}' looks like an IP address but does not parse "
            "as one"
        )
        raise ValueError(msg)

    # Fall back to hostname
    if _HOSTNAME_PATTERN.match(target):
        return target

    msg = (
        f"target '{target}' is not a valid hostname, IP address, or CIDR range"
    )
    raise ValueError(msg)


def _validate_port_spec(ports: str) -> str:
    """Validate an nmap-style port specification.

    Accepts: "80", "1-1000", "22,80,443", "1-1000,8080".

    Raises:
        ValueError: If the spec does not parse.
    """
    ports = ports.strip()
    if not ports:
        msg = "ports must not be empty"
        raise ValueError(msg)
    if not _PORT_SPEC_PATTERN.match(ports):
        msg = (
            f"ports '{ports}' is not a valid port spec "
            "(use '80', '1-1000', or '22,80,443')"
        )
        raise ValueError(msg)
    # Validate numeric ranges
    for chunk in ports.split(","):
        if "-" in chunk:
            low_str, high_str = chunk.split("-", 1)
            low, high = int(low_str), int(high_str)
            if not (_MIN_PORT <= low <= high <= _MAX_PORT):
                msg = (
                    f"port range '{chunk}' is out of bounds "
                    f"({_MIN_PORT}-{_MAX_PORT})"
                )
                raise ValueError(msg)
        else:
            port = int(chunk)
            if not _MIN_PORT <= port <= _MAX_PORT:
                msg = (
                    f"port {port} is out of bounds "
                    f"({_MIN_PORT}-{_MAX_PORT})"
                )
                raise ValueError(msg)
    return ports


def _check_target_allowlist(target: str, allowlist: Iterable[str]) -> None:
    """Reject targets that fall outside the configured allowlist.

    A target passes if it equals an allowlist entry, or if it (as IP)
    falls within an allowlist CIDR network. Hostnames are matched only
    by exact string equality (no DNS resolution; this is deliberate).

    Raises:
        ValueError: If allowlist is non-empty and target does not match.
    """
    allowlist = list(allowlist)
    if not allowlist:
        return

    # Exact match wins
    if target in allowlist:
        return

    # CIDR-network containment: try both directions
    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        target_ip = None

    for entry in allowlist:
        try:
            entry_net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if target_ip is not None and target_ip in entry_net:
            return
        # Allow scanning a CIDR that's a subset of an allowed CIDR
        try:
            target_net = ipaddress.ip_network(target, strict=False)
            if target_net.subnet_of(entry_net):
                return
        except ValueError:
            continue

    msg = (
        f"target '{target}' is not in the configured target allowlist. "
        f"Allowed: {allowlist}"
    )
    raise ValueError(msg)


def _validate_timeout(timeout: int | None) -> int:
    """Clamp timeout to the configured ceiling, default if missing."""
    if timeout is None:
        return _DEFAULT_TIMEOUT_SECONDS
    if timeout < 1:
        msg = "timeout must be >= 1 second"
        raise ValueError(msg)
    return min(timeout, _MAX_TIMEOUT_SECONDS)


# ---- Nmap invocation -------------------------------------------------------


async def _run_nmap(args: list[str], *, timeout: int) -> dict[str, Any]:
    """Run nmap with the given args and return a structured result.

    Returns a dict with: command, returncode, stdout, stderr, timed_out.
    Never raises for nmap failures — those are surfaced in the result.
    """
    full_command = [_CONFIG.nmap_path, *args]
    _log.info("running: %s", " ".join(full_command))

    try:
        proc = await asyncio.create_subprocess_exec(
            *full_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return {
            "command": full_command,
            "returncode": -1,
            "stdout": "",
            "stderr": f"nmap binary not found at '{_CONFIG.nmap_path}': {exc}",
            "timed_out": False,
        }

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        timed_out = False
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return {
            "command": full_command,
            "returncode": -1,
            "stdout": "",
            "stderr": f"nmap timed out after {timeout}s",
            "timed_out": True,
        }

    return {
        "command": full_command,
        "returncode": proc.returncode if proc.returncode is not None else -1,
        "stdout": stdout_bytes.decode("utf-8", errors="replace"),
        "stderr": stderr_bytes.decode("utf-8", errors="replace"),
        "timed_out": timed_out,
    }


# ---- Server and tools ------------------------------------------------------


mcp = FastMCP("pathfinder-nmap")


@mcp.tool()
async def nmap_discover(
    target: str,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Host discovery (ping sweep) over a target range.

    Equivalent to ``nmap -sn <target>``. Identifies which hosts in the
    range are alive without scanning any ports.

    Args:
        target: Hostname, IP address, or CIDR range. Must pass server-
            side validation. If a target allowlist is configured, the
            target must fall within it.
        timeout_seconds: Optional per-call timeout. Defaults to 60.
            Clamped to a hard ceiling of 300.

    Returns:
        A dict with keys: ``operation``, ``target``, ``command`` (the full
        argv used), ``returncode``, ``stdout``, ``stderr``, ``timed_out``.
    """
    target = _validate_target(target)
    _check_target_allowlist(target, _CONFIG.target_allowlist)
    timeout = _validate_timeout(timeout_seconds)

    args = ["-sn", target]
    result = await _run_nmap(args, timeout=timeout)
    return {"operation": "nmap_discover", "target": target, **result}


@mcp.tool()
async def nmap_port_scan(
    target: str,
    ports: str = "1-1000",
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """TCP connect scan of specified ports on a target.

    Equivalent to ``nmap -sT -p <ports> <target>``. TCP connect scanning
    does not require root/admin privileges and is the safe default for
    cross-platform use.

    Args:
        target: Hostname, IP address, or CIDR range.
        ports: Port specification, e.g. ``"80"``, ``"1-1000"``, or
            ``"22,80,443"``. Defaults to ``"1-1000"``.
        timeout_seconds: Optional per-call timeout. Defaults to 60.

    Returns:
        Structured nmap output (see ``nmap_discover``).
    """
    target = _validate_target(target)
    _check_target_allowlist(target, _CONFIG.target_allowlist)
    ports = _validate_port_spec(ports)
    timeout = _validate_timeout(timeout_seconds)

    args = ["-sT", "-p", ports, target]
    result = await _run_nmap(args, timeout=timeout)
    return {
        "operation": "nmap_port_scan",
        "target": target,
        "ports": ports,
        **result,
    }


@mcp.tool()
async def nmap_version_scan(
    target: str,
    ports: str = "1-1000",
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Service version detection on specified ports.

    Equivalent to ``nmap -sT -sV -p <ports> <target>``. Probes open
    ports to identify running service versions. Slower than a plain
    port scan; per-call timeout default may need to be increased for
    large port ranges.

    Args:
        target: Hostname, IP address, or CIDR range.
        ports: Port specification. Defaults to ``"1-1000"``.
        timeout_seconds: Optional per-call timeout. Defaults to 60.

    Returns:
        Structured nmap output.
    """
    target = _validate_target(target)
    _check_target_allowlist(target, _CONFIG.target_allowlist)
    ports = _validate_port_spec(ports)
    timeout = _validate_timeout(timeout_seconds)

    args = ["-sT", "-sV", "-p", ports, target]
    result = await _run_nmap(args, timeout=timeout)
    return {
        "operation": "nmap_version_scan",
        "target": target,
        "ports": ports,
        **result,
    }


# ---- Entrypoint ------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Nmap MCP server (Pathfinder).",
    )
    parser.add_argument(
        "--target-allowlist",
        action="append",
        default=[],
        metavar="HOST_OR_CIDR",
        help=(
            "Restrict scans to this host/CIDR. Repeatable. If omitted, "
            "no server-side target check is applied."
        ),
    )
    parser.add_argument(
        "--nmap-path",
        default=None,
        help=(
            "Override the nmap binary path. Defaults to the 'nmap' "
            "executable found on PATH."
        ),
    )
    return parser.parse_args(argv)


def _resolve_nmap_path(override: str | None) -> str:
    """Locate the nmap binary. Use override if given, otherwise PATH."""
    if override:
        if not Path(override).is_file():
            msg = f"--nmap-path '{override}' does not exist"
            raise FileNotFoundError(msg)
        return override
    found = shutil.which("nmap")
    if found is None:
        msg = (
            "nmap binary not found on PATH. Install nmap or pass "
            "--nmap-path to specify its location."
        )
        raise FileNotFoundError(msg)
    return found


def main(argv: list[str] | None = None) -> None:
    """Configure the server and run it on stdio transport."""
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,  # stdout is the MCP transport
    )

    _CONFIG.target_allowlist = list(args.target_allowlist)
    _CONFIG.nmap_path = _resolve_nmap_path(args.nmap_path)

    _log.info(
        "starting nmap MCP server (nmap=%s, allowlist=%s)",
        _CONFIG.nmap_path,
        _CONFIG.target_allowlist or "<unrestricted>",
    )
    mcp.run()


if __name__ == "__main__":
    main()

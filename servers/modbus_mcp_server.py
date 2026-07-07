"""Modbus TCP MCP server.

A standalone MCP server that exposes read-only Modbus operations over
TCP. The server provides four named operations corresponding to the
four Modbus read function codes:

* ``modbus_read_coils``               (FC1, single-bit writable registers)
* ``modbus_read_discrete_inputs``     (FC2, single-bit read-only inputs)
* ``modbus_read_holding_registers``   (FC3, 16-bit writable registers)
* ``modbus_read_input_registers``     (FC4, 16-bit read-only inputs)

Read-only contract
==================

This server is **read-only by construction**. The pymodbus library is
imported with the read-side client functions only; write functions
(``write_coil``, ``write_register``, ``write_coils``, ``write_registers``)
are not imported, not aliased, and not called anywhere in this file.

Verifying the read-only property is a simple file-level check:

* ``grep -E 'write_coil|write_register|write_coils|write_registers'
  scripts/mcp_servers/modbus_mcp_server.py`` returns no matches.

Capability claims in research outputs (e.g. "Pathfinder cannot write
to Modbus targets through this MCP server") rest on this property.

Safety model
============

* Targets must validate as hostname, IP address, or CIDR-bounded host.
* Optional target allowlist (off by default; configured at startup).
* Register address and count are bounded (Modbus addresses are 16-bit;
  counts are capped at protocol maxima per function code).
* Unit ID (slave ID) bounded to 0-247 per Modbus spec.
* Per-call timeout, default 10 seconds, capped at 60.

Run standalone for inspection:

.. code-block:: bash

    uv run mcp dev scripts/mcp_servers/modbus_mcp_server.py

Run as stdio subprocess:

.. code-block:: bash

    uv run python scripts/mcp_servers/modbus_mcp_server.py
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import re
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# Only the async TCP client is imported. The pymodbus library DOES include
# write functions; we DO NOT import or alias them in this file. The
# read-only property is enforced by the absence of those names here.
from mcp.server.fastmcp import FastMCP
from pymodbus.client import AsyncModbusTcpClient

_log = logging.getLogger("modbus_mcp_server")

# ---- Constants -------------------------------------------------------------

_DEFAULT_TIMEOUT_SECONDS = 10
_MAX_TIMEOUT_SECONDS = 60

_DEFAULT_MODBUS_PORT = 502
_MIN_PORT = 1
_MAX_PORT = 65535

# Modbus register address space is 16-bit.
_MIN_ADDRESS = 0
_MAX_ADDRESS = 65535

# Modbus unit (slave) ID range per the specification.
_MIN_UNIT_ID = 0
_MAX_UNIT_ID = 247

# Protocol-maximum read counts per function code. Per Modbus TCP spec:
# FC1, FC2 (bit reads):  up to 2000 coils/inputs per request
# FC3, FC4 (word reads): up to 125 registers per request
_MAX_BIT_COUNT = 2000
_MAX_WORD_COUNT = 125

# Conservative hostname pattern (mirrors nmap_mcp_server).
_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


# ---- Server configuration --------------------------------------------------


@dataclass
class ServerConfig:
    """Runtime configuration applied at server startup."""

    target_allowlist: list[str] = field(default_factory=list)


_CONFIG = ServerConfig()


# ---- Validation helpers ----------------------------------------------------


def _validate_host(host: str) -> str:
    """Validate that ``host`` is a hostname or IP address."""
    host = host.strip()
    if not host:
        msg = "host must not be empty"
        raise ValueError(msg)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return host
    if re.match(r"^\d+(\.\d+)*$", host):
        msg = f"host '{host}' looks like an IP but does not parse as one"
        raise ValueError(msg)
    if _HOSTNAME_PATTERN.match(host):
        return host
    msg = f"host '{host}' is not a valid hostname or IP address"
    raise ValueError(msg)


def _validate_port(port: int) -> int:
    if not _MIN_PORT <= port <= _MAX_PORT:
        msg = f"port {port} is out of bounds ({_MIN_PORT}-{_MAX_PORT})"
        raise ValueError(msg)
    return port


def _validate_address(address: int) -> int:
    if not _MIN_ADDRESS <= address <= _MAX_ADDRESS:
        msg = (
            f"register address {address} out of bounds "
            f"({_MIN_ADDRESS}-{_MAX_ADDRESS})"
        )
        raise ValueError(msg)
    return address


def _validate_bit_count(count: int) -> int:
    if not 1 <= count <= _MAX_BIT_COUNT:
        msg = (
            f"bit-read count {count} out of bounds (1-{_MAX_BIT_COUNT}); "
            "Modbus FC1/FC2 maximum is 2000 per request"
        )
        raise ValueError(msg)
    return count


def _validate_word_count(count: int) -> int:
    if not 1 <= count <= _MAX_WORD_COUNT:
        msg = (
            f"word-read count {count} out of bounds (1-{_MAX_WORD_COUNT}); "
            "Modbus FC3/FC4 maximum is 125 per request"
        )
        raise ValueError(msg)
    return count


def _validate_unit_id(unit_id: int) -> int:
    if not _MIN_UNIT_ID <= unit_id <= _MAX_UNIT_ID:
        msg = (
            f"unit_id {unit_id} out of bounds "
            f"({_MIN_UNIT_ID}-{_MAX_UNIT_ID}); Modbus spec limit"
        )
        raise ValueError(msg)
    return unit_id


def _validate_timeout(timeout: int | None) -> int:
    if timeout is None:
        return _DEFAULT_TIMEOUT_SECONDS
    if timeout < 1:
        msg = "timeout must be >= 1 second"
        raise ValueError(msg)
    return min(timeout, _MAX_TIMEOUT_SECONDS)


def _check_target_allowlist(host: str, allowlist: Iterable[str]) -> None:
    """Reject hosts outside the configured allowlist (if any)."""
    allowlist = list(allowlist)
    if not allowlist:
        return

    if host in allowlist:
        return

    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        host_ip = None

    for entry in allowlist:
        try:
            entry_net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if host_ip is not None and host_ip in entry_net:
            return

    msg = (
        f"host '{host}' is not in the configured target allowlist. "
        f"Allowed: {allowlist}"
    )
    raise ValueError(msg)


# ---- Connection lifecycle --------------------------------------------------


async def _open_client(
    host: str, port: int, timeout: int
) -> AsyncModbusTcpClient:
    """Connect to a Modbus TCP server with a connection timeout."""
    client = AsyncModbusTcpClient(host=host, port=port, timeout=timeout)
    try:
        await asyncio.wait_for(client.connect(), timeout=timeout)
    except TimeoutError:
        msg = f"connection to {host}:{port} timed out after {timeout}s"
        raise ConnectionError(msg) from None
    if not client.connected:
        msg = f"failed to connect to {host}:{port}"
        raise ConnectionError(msg)
    return client


async def _close_client(client: AsyncModbusTcpClient) -> None:
    """Close a Modbus TCP client connection, best-effort."""
    try:
        client.close()
    except Exception:  # connection close is best-effort
        _log.debug("client.close raised; ignoring", exc_info=True)


def _summarise_response(response: Any) -> dict[str, Any]:
    """Translate a pymodbus response object into a JSON-serialisable dict."""
    if response is None:
        return {"success": False, "error": "no response from server"}
    if response.isError():
        return {
            "success": False,
            "error": str(response),
            "exception_code": getattr(response, "exception_code", None),
        }
    payload: dict[str, Any] = {"success": True}
    # FC1, FC2: bit lists are in `bits`
    if hasattr(response, "bits") and response.bits is not None:
        payload["bits"] = [bool(b) for b in response.bits]
    # FC3, FC4: register lists are in `registers`
    if hasattr(response, "registers") and response.registers is not None:
        payload["registers"] = [int(r) for r in response.registers]
    return payload


# ---- Server and tools ------------------------------------------------------


mcp = FastMCP("pathfinder-modbus")


@mcp.tool()
async def modbus_read_coils(
    host: str,
    address: int,
    count: int = 1,
    port: int = _DEFAULT_MODBUS_PORT,
    unit_id: int = 1,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Read coil values from a Modbus TCP server (function code 1).

    Coils are single-bit writable registers, typically used for digital
    output state (e.g. pump enable). This operation reads them without
    modifying them.

    Args:
        host: Target hostname or IP address.
        address: Starting coil address (0-65535).
        count: Number of coils to read (1-2000).
        port: TCP port (default 502).
        unit_id: Modbus unit (slave) ID (0-247, default 1).
        timeout_seconds: Per-call timeout, default 10, max 60.

    Returns:
        A dict with ``operation``, ``host``, ``port``, ``address``,
        ``count``, ``success``, and on success a ``bits`` list.
    """
    host = _validate_host(host)
    _check_target_allowlist(host, _CONFIG.target_allowlist)
    address = _validate_address(address)
    count = _validate_bit_count(count)
    port = _validate_port(port)
    unit_id = _validate_unit_id(unit_id)
    timeout = _validate_timeout(timeout_seconds)

    _log.info("modbus_read_coils host=%s port=%d addr=%d count=%d",
              host, port, address, count)
    start = time.perf_counter()
    try:
        client = await _open_client(host, port, timeout)
        try:
            response = await client.read_coils(
                address=address, count=count, device_id=unit_id
            )
        finally:
            await _close_client(client)
        result = _summarise_response(response)
    except (TimeoutError, ConnectionError, OSError) as exc:
        result = {"success": False, "error": str(exc)}
    duration_ms = (time.perf_counter() - start) * 1000

    return {
        "operation": "modbus_read_coils",
        "host": host,
        "port": port,
        "address": address,
        "count": count,
        "unit_id": unit_id,
        "duration_ms": duration_ms,
        **result,
    }


@mcp.tool()
async def modbus_read_discrete_inputs(
    host: str,
    address: int,
    count: int = 1,
    port: int = _DEFAULT_MODBUS_PORT,
    unit_id: int = 1,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Read discrete input values from a Modbus TCP server (function code 2).

    Discrete inputs are single-bit read-only inputs, typically used for
    digital sensor state.

    Returns the same structure as ``modbus_read_coils`` with ``bits``.
    """
    host = _validate_host(host)
    _check_target_allowlist(host, _CONFIG.target_allowlist)
    address = _validate_address(address)
    count = _validate_bit_count(count)
    port = _validate_port(port)
    unit_id = _validate_unit_id(unit_id)
    timeout = _validate_timeout(timeout_seconds)

    _log.info("modbus_read_discrete_inputs host=%s port=%d addr=%d count=%d",
              host, port, address, count)
    start = time.perf_counter()
    try:
        client = await _open_client(host, port, timeout)
        try:
            response = await client.read_discrete_inputs(
                address=address, count=count, device_id=unit_id
            )
        finally:
            await _close_client(client)
        result = _summarise_response(response)
    except (TimeoutError, ConnectionError, OSError) as exc:
        result = {"success": False, "error": str(exc)}
    duration_ms = (time.perf_counter() - start) * 1000

    return {
        "operation": "modbus_read_discrete_inputs",
        "host": host,
        "port": port,
        "address": address,
        "count": count,
        "unit_id": unit_id,
        "duration_ms": duration_ms,
        **result,
    }


@mcp.tool()
async def modbus_read_holding_registers(
    host: str,
    address: int,
    count: int = 1,
    port: int = _DEFAULT_MODBUS_PORT,
    unit_id: int = 1,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Read holding registers from a Modbus TCP server (function code 3).

    Holding registers are 16-bit writable registers, typically used for
    setpoints and configuration. This operation reads them without
    modifying them.

    Returns ``registers`` on success: a list of integers (0-65535 each).
    """
    host = _validate_host(host)
    _check_target_allowlist(host, _CONFIG.target_allowlist)
    address = _validate_address(address)
    count = _validate_word_count(count)
    port = _validate_port(port)
    unit_id = _validate_unit_id(unit_id)
    timeout = _validate_timeout(timeout_seconds)

    _log.info("modbus_read_holding_registers host=%s port=%d addr=%d count=%d",
              host, port, address, count)
    start = time.perf_counter()
    try:
        client = await _open_client(host, port, timeout)
        try:
            response = await client.read_holding_registers(
                address=address, count=count, device_id=unit_id
            )
        finally:
            await _close_client(client)
        result = _summarise_response(response)
    except (TimeoutError, ConnectionError, OSError) as exc:
        result = {"success": False, "error": str(exc)}
    duration_ms = (time.perf_counter() - start) * 1000

    return {
        "operation": "modbus_read_holding_registers",
        "host": host,
        "port": port,
        "address": address,
        "count": count,
        "unit_id": unit_id,
        "duration_ms": duration_ms,
        **result,
    }


@mcp.tool()
async def modbus_read_input_registers(
    host: str,
    address: int,
    count: int = 1,
    port: int = _DEFAULT_MODBUS_PORT,
    unit_id: int = 1,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Read input registers from a Modbus TCP server (function code 4).

    Input registers are 16-bit read-only registers, typically used for
    sensor readings.

    Returns ``registers`` on success.
    """
    host = _validate_host(host)
    _check_target_allowlist(host, _CONFIG.target_allowlist)
    address = _validate_address(address)
    count = _validate_word_count(count)
    port = _validate_port(port)
    unit_id = _validate_unit_id(unit_id)
    timeout = _validate_timeout(timeout_seconds)

    _log.info("modbus_read_input_registers host=%s port=%d addr=%d count=%d",
              host, port, address, count)
    start = time.perf_counter()
    try:
        client = await _open_client(host, port, timeout)
        try:
            response = await client.read_input_registers(
                address=address, count=count, device_id=unit_id
            )
        finally:
            await _close_client(client)
        result = _summarise_response(response)
    except (TimeoutError, ConnectionError, OSError) as exc:
        result = {"success": False, "error": str(exc)}
    duration_ms = (time.perf_counter() - start) * 1000

    return {
        "operation": "modbus_read_input_registers",
        "host": host,
        "port": port,
        "address": address,
        "count": count,
        "unit_id": unit_id,
        "duration_ms": duration_ms,
        **result,
    }


# ---- Entrypoint ------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only Modbus TCP MCP server (Pathfinder).",
    )
    parser.add_argument(
        "--target-allowlist",
        action="append",
        default=[],
        metavar="HOST_OR_CIDR",
        help=(
            "Restrict Modbus reads to this host/CIDR. Repeatable. "
            "If omitted, no server-side host check is applied."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Configure the server and run it on stdio transport."""
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    _CONFIG.target_allowlist = list(args.target_allowlist)
    _log.info(
        "starting Modbus MCP server (allowlist=%s)",
        _CONFIG.target_allowlist or "<unrestricted>",
    )
    mcp.run()


if __name__ == "__main__":
    main()

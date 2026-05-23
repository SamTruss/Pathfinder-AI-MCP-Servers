"""HTTP authentication check MCP server.

A standalone MCP server that exposes named operations for validating
HTTP authentication credentials against a target URL. The server is
deliberately narrow: it does not perform general HTTP requests, only
authentication-style logins with structured success/failure signals.

Safety model:

* Two named tools: ``http_form_login`` and ``http_basic_auth``. The
  caller chooses based on what the target uses.
* The server returns status code, response size, cookie-set flag, and
  redirect target. It does NOT return the response body — protecting
  the agent from response-injection content that the LLM might later
  reason about.
* Optional target allowlist (off by default; configured at startup via
  ``--target-allowlist``).
* Per-call timeout, default 30 seconds, hard ceiling 60 seconds.
* HTTPS verification is enabled by default; ``--allow-insecure-https``
  switches it off for self-signed certs in lab environments.

This server sends credentials over the network. That is its function.
It is intentionally not a general HTTP client.

Run standalone for inspection:

.. code-block:: bash

    uv run mcp dev scripts/mcp_servers/http_auth_mcp_server.py

Run as stdio subprocess:

.. code-block:: bash

    uv run python scripts/mcp_servers/http_auth_mcp_server.py
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP

_log = logging.getLogger("http_auth_mcp_server")

# ---- Constants -------------------------------------------------------------

_MAX_TIMEOUT_SECONDS = 60
_DEFAULT_TIMEOUT_SECONDS = 30

# Username and password fields longer than this are almost certainly the
# wrong shape (e.g. someone passing a whole payload). Reject early.
_MAX_CREDENTIAL_LENGTH = 200

# Form-field name lengths.
_MAX_FIELD_NAME_LENGTH = 64


# ---- Server configuration --------------------------------------------------


@dataclass
class ServerConfig:
    """Runtime configuration applied at server startup.

    Attributes:
        target_allowlist: Hosts/IPs/CIDRs scans are restricted to.
            Matched against the URL's host. Empty = no server-side check.
        allow_insecure_https: If True, HTTPS certificate validation is
            disabled. Use only for lab environments with self-signed
            certificates.
    """

    target_allowlist: list[str] = field(default_factory=list)
    allow_insecure_https: bool = False


_CONFIG = ServerConfig()


# ---- Validation helpers ----------------------------------------------------


def _validate_url(url: str) -> str:
    """Validate that ``url`` is a well-formed http or https URL."""
    url = url.strip()
    if not url:
        msg = "url must not be empty"
        raise ValueError(msg)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        msg = f"url scheme must be http or https, got '{parsed.scheme}'"
        raise ValueError(msg)
    if not parsed.netloc:
        msg = f"url '{url}' has no host component"
        raise ValueError(msg)
    return url


def _validate_credential(value: str, name: str) -> str:
    """Validate that a credential value is non-empty and bounded in length."""
    if not value:
        msg = f"{name} must not be empty"
        raise ValueError(msg)
    if len(value) > _MAX_CREDENTIAL_LENGTH:
        msg = (
            f"{name} exceeds maximum length ({len(value)} > "
            f"{_MAX_CREDENTIAL_LENGTH}); likely the wrong shape of argument"
        )
        raise ValueError(msg)
    return value


def _validate_field_name(value: str, name: str) -> str:
    """Validate that a form field name is a reasonable identifier."""
    value = value.strip()
    if not value:
        msg = f"{name} must not be empty"
        raise ValueError(msg)
    if len(value) > _MAX_FIELD_NAME_LENGTH:
        msg = f"{name} exceeds maximum length"
        raise ValueError(msg)
    return value


def _validate_timeout(timeout: int | None) -> int:
    if timeout is None:
        return _DEFAULT_TIMEOUT_SECONDS
    if timeout < 1:
        msg = "timeout must be >= 1 second"
        raise ValueError(msg)
    return min(timeout, _MAX_TIMEOUT_SECONDS)


def _check_target_allowlist(url: str, allowlist: Iterable[str]) -> None:
    """Reject URLs whose host is not in the configured allowlist."""
    allowlist = list(allowlist)
    if not allowlist:
        return

    host = urlparse(url).hostname or ""

    # Exact host match
    if host in allowlist:
        return

    # IP-in-CIDR match
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
        f"host '{host}' (from url '{url}') is not in the configured target "
        f"allowlist. Allowed: {allowlist}"
    )
    raise ValueError(msg)


# ---- HTTP execution --------------------------------------------------------


async def _post_form(
    url: str,
    data: dict[str, str],
    *,
    timeout: int,
) -> dict[str, Any]:
    """POST form data and return a structured signal-set (never the body)."""
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=not _CONFIG.allow_insecure_https,
        ) as client:
            resp = await client.post(url, data=data)
    except httpx.HTTPError as exc:
        return {
            "status_code": -1,
            "error": f"HTTP error: {exc}",
            "duration_ms": (time.perf_counter() - start) * 1000,
        }
    return _summarise_response(resp, start)


async def _get_with_basic_auth(
    url: str,
    username: str,
    password: str,
    *,
    timeout: int,
) -> dict[str, Any]:
    """GET with HTTP Basic Auth and return a structured signal-set."""
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=not _CONFIG.allow_insecure_https,
        ) as client:
            resp = await client.get(url, auth=(username, password))
    except httpx.HTTPError as exc:
        return {
            "status_code": -1,
            "error": f"HTTP error: {exc}",
            "duration_ms": (time.perf_counter() - start) * 1000,
        }
    return _summarise_response(resp, start)


def _summarise_response(resp: httpx.Response, start: float) -> dict[str, Any]:
    """Extract signal-bearing fields from an HTTP response without the body."""
    duration_ms = (time.perf_counter() - start) * 1000
    cookies_set = list(resp.cookies)
    redirect = resp.headers.get("location") if resp.is_redirect else None
    return {
        "status_code": resp.status_code,
        "response_bytes": len(resp.content),
        "cookies_set": cookies_set,
        "redirect_target": redirect,
        "is_redirect": resp.is_redirect,
        "content_type": resp.headers.get("content-type"),
        "duration_ms": duration_ms,
    }


# ---- Server and tools ------------------------------------------------------


mcp = FastMCP("pathfinder-http-auth")


@mcp.tool()
async def http_form_login(
    url: str,
    username: str,
    password: str,
    username_field: str = "username",
    password_field: str = "password",  # noqa: S107 - form field name, not a credential
    extra_fields: dict[str, str] | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """POST a form-based login and return structured success/failure signals.

    Suitable for ICS web UIs (OpenPLC, Scada-LTS) and most IT login forms.
    The server does NOT return the response body, only:

    * ``status_code`` (HTTP status)
    * ``response_bytes`` (size of the body, useful for distinguishing
      login-page-redisplayed from main-dashboard)
    * ``cookies_set`` (names of any cookies the server set, a strong
      success signal)
    * ``redirect_target`` (a redirect away from the login page typically
      indicates success)
    * ``is_redirect``
    * ``content_type``
    * ``duration_ms``

    Args:
        url: The form-submit URL.
        username: Username to send. Bounded length.
        password: Password to send. Bounded length.
        username_field: Form field name for the username (default
            ``"username"``).
        password_field: Form field name for the password (default
            ``"password"``).
        extra_fields: Optional extra form fields (e.g. CSRF tokens,
            hidden fields).
        timeout_seconds: Per-call timeout, default 30, capped at 60.
    """
    url = _validate_url(url)
    _check_target_allowlist(url, _CONFIG.target_allowlist)
    username = _validate_credential(username, "username")
    password = _validate_credential(password, "password")
    username_field = _validate_field_name(username_field, "username_field")
    password_field = _validate_field_name(password_field, "password_field")
    timeout = _validate_timeout(timeout_seconds)

    data = {username_field: username, password_field: password}
    if extra_fields:
        for key, value in extra_fields.items():
            _validate_field_name(key, "extra_fields key")
            _validate_credential(value, f"extra_fields[{key}]")
            data[key] = value

    _log.info("http_form_login: POST %s (user=%s)", url, username)
    result = await _post_form(url, data, timeout=timeout)
    return {
        "operation": "http_form_login",
        "url": url,
        "username": username,
        **result,
    }


@mcp.tool()
async def http_basic_auth(
    url: str,
    username: str,
    password: str,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """GET a URL with HTTP Basic Auth and return structured signals.

    Suitable for embedded devices and APIs that use RFC 7617 Basic Auth.
    Same return shape as ``http_form_login``.
    """
    url = _validate_url(url)
    _check_target_allowlist(url, _CONFIG.target_allowlist)
    username = _validate_credential(username, "username")
    password = _validate_credential(password, "password")
    timeout = _validate_timeout(timeout_seconds)

    _log.info("http_basic_auth: GET %s (user=%s)", url, username)
    result = await _get_with_basic_auth(url, username, password, timeout=timeout)
    return {
        "operation": "http_basic_auth",
        "url": url,
        "username": username,
        **result,
    }


# ---- Entrypoint ------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HTTP authentication check MCP server (Pathfinder).",
    )
    parser.add_argument(
        "--target-allowlist",
        action="append",
        default=[],
        metavar="HOST_OR_CIDR",
        help=(
            "Restrict auth checks to this host/CIDR. Repeatable. "
            "If omitted, no server-side host check is applied."
        ),
    )
    parser.add_argument(
        "--allow-insecure-https",
        action="store_true",
        help=(
            "Disable HTTPS certificate verification. Use only for lab "
            "environments with self-signed certificates."
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
    _CONFIG.allow_insecure_https = args.allow_insecure_https
    _log.info(
        "starting HTTP auth MCP server (allowlist=%s, insecure_https=%s)",
        _CONFIG.target_allowlist or "<unrestricted>",
        _CONFIG.allow_insecure_https,
    )
    mcp.run()


if __name__ == "__main__":
    main()

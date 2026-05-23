"""CVE lookup MCP server.

Queries the NIST National Vulnerability Database (NVD) CVE API 2.0 to
look up real CVE records by keyword (e.g., 'Werkzeug 0.16.0') or by
exact CVE ID. Returns structured records including CVSS scores, CWE
mappings, and references — backed by an authoritative source rather
than LLM-fabricated severity ratings.

This is the report-phase tool that converts the agent's findings from
"the model thinks this is high severity" to "NVD records CVE-2023-46136
affecting this component, CVSS v3.1: 8.2".

NVD API documentation: https://nvd.nist.gov/developers/vulnerabilities

Rate limits: Without an API key, NVD allows ~5 requests per 30 seconds.
For higher throughput, set the NVD_API_KEY environment variable and the
server will include it in requests.

Two named operations are exposed:

- ``cve_search`` — keyword search (e.g., 'Werkzeug 0.16.0',
  'Apache Tomcat'). Returns up to ``max_results`` CVE records sorted
  by CVSS severity (highest first).
- ``cve_lookup`` — exact CVE ID lookup (e.g., 'CVE-2023-46136').
  Returns a single CVE record or an error if not found.

Both operations return a compact view: cve_id, title (first 80 chars
of description), cvss_v3_score, cvss_v3_severity, cwe_ids (list),
published_date, references (up to 3 URLs). Full descriptions are
truncated to 500 chars to keep token usage reasonable in agent
prompts. The compact view is by design — the agent doesn't need raw
NVD JSON, it needs decision-supporting evidence.

The server enforces sane query bounds: keywords must be 3-100 chars,
max_results is capped at 10, CVE IDs must match the standard pattern.
This aligns with Pathfinder's governance-first design — every input
into a security-critical tool is validated at the server boundary.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

_log = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CVE ID pattern: CVE-YYYY-NNNN+
_CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Tunable constants
_MIN_KEYWORD_LEN = 3
_MAX_KEYWORD_LEN = 100
_MAX_RESULTS_CAP = 10
_DEFAULT_RESULTS = 5
_HTTP_TIMEOUT_SECONDS = 30.0
_DESCRIPTION_TRUNCATE = 500
_TITLE_TRUNCATE = 80
_MAX_REFERENCES_RETURNED = 3

CVE_SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "keyword": {
            "type": "string",
            "description": (
                "Search keyword. Examples: 'Werkzeug 0.16.0', 'Apache Tomcat', "
                "'OpenSSH 8.0'. Be specific — broad terms return too many results."
            ),
            "minLength": _MIN_KEYWORD_LEN,
            "maxLength": _MAX_KEYWORD_LEN,
        },
        "max_results": {
            "type": "integer",
            "description": (
                f"Maximum number of CVE records to return "
                f"(1-{_MAX_RESULTS_CAP}, default {_DEFAULT_RESULTS}). "
                f"Results are sorted by CVSS v3 severity, highest first."
            ),
            "minimum": 1,
            "maximum": _MAX_RESULTS_CAP,
        },
    },
    "required": ["keyword"],
    "additionalProperties": False,
}

CVE_LOOKUP_SCHEMA = {
    "type": "object",
    "properties": {
        "cve_id": {
            "type": "string",
            "description": (
                "Exact CVE identifier (e.g., 'CVE-2023-46136'). "
                "Must match the format CVE-YYYY-NNNN+."
            ),
            "pattern": r"^CVE-\d{4}-\d{4,}$",
        },
    },
    "required": ["cve_id"],
    "additionalProperties": False,
}


class CVEServer:
    """MCP server exposing CVE lookup tools backed by NVD."""

    def __init__(self, api_key: str | None = None) -> None:
        self._server = Server("cve-mcp-server")
        # API key is optional but recommended for thesis-level usage;
        # NVD's unauthenticated rate limit is too low for sustained runs.
        self._api_key = api_key or os.environ.get("NVD_API_KEY")

        @self._server.list_tools()
        async def list_tools() -> list[Tool]:
            return self.get_tool_definitions()

        @self._server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
            if name == "cve_search":
                return await self._handle_cve_search(**arguments)
            if name == "cve_lookup":
                return await self._handle_cve_lookup(**arguments)
            return _error_response(f"Unknown tool: {name}")


    def get_tool_definitions(self) -> list[Tool]:
        """Return the list of tools exposed by this server."""
        return [
            Tool(
                name="cve_search",
                description=(
                    "Search the NIST National Vulnerability Database (NVD) "
                    "by keyword. Returns CVE records with CVSS scores, CWE "
                    "mappings, and references. Use this to validate findings "
                    "against authoritative vulnerability data — e.g., search "
                    "'Werkzeug 0.16.0' to confirm known CVEs affect that "
                    "version. Results are sorted by CVSS severity, highest first."
                ),
                inputSchema=CVE_SEARCH_SCHEMA,
            ),
            Tool(
                name="cve_lookup",
                description=(
                    "Look up a single CVE record by its exact ID "
                    "(e.g., 'CVE-2023-46136'). Returns the full CVE record "
                    "from NVD including description, CVSS scoring, affected "
                    "products, CWE references, and external links. Use this "
                    "to cite specific CVEs in findings."
                ),
                inputSchema=CVE_LOOKUP_SCHEMA,
            ),
        ]

    async def _handle_cve_search(
        self, keyword: str, max_results: int = _DEFAULT_RESULTS
    ) -> list[TextContent]:
        """Handle keyword-based CVE search."""
        # Validate inputs
        errors = self._validate_search(keyword, max_results)
        if errors:
            return _error_response("; ".join(errors))

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
        }

        try:
            data = await self._call_nvd(params)
        except httpx.HTTPError as exc:
            _log.warning("NVD request failed: %s", exc)
            return _error_response(f"NVD API error: {exc}")
        except Exception as exc:
            _log.exception("Unexpected error calling NVD")
            return _error_response(f"Unexpected error: {exc}")

        vulnerabilities = data.get("vulnerabilities", [])
        records = [self._compact_record(v.get("cve", {})) for v in vulnerabilities]
        # Sort by CVSS v3 score descending (None scores last)
        records.sort(
            key=lambda r: (r.get("cvss_v3_score") is None, -(r.get("cvss_v3_score") or 0))
        )

        result = {
            "keyword": keyword,
            "total_results": data.get("totalResults", 0),
            "returned": len(records),
            "cves": records,
        }
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    async def _handle_cve_lookup(self, cve_id: str) -> list[TextContent]:
        """Handle exact CVE ID lookup."""
        if not _CVE_ID_PATTERN.match(cve_id):
            return _error_response(
                f"cve_id '{cve_id}' does not match the format CVE-YYYY-NNNN"
            )

        params = {"cveId": cve_id}

        try:
            data = await self._call_nvd(params)
        except httpx.HTTPError as exc:
            _log.warning("NVD request failed: %s", exc)
            return _error_response(f"NVD API error: {exc}")
        except Exception as exc:
            _log.exception("Unexpected error calling NVD")
            return _error_response(f"Unexpected error: {exc}")

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return _error_response(f"No CVE record found for '{cve_id}'")

        cve_record = vulnerabilities[0].get("cve", {})
        return [
            TextContent(
                type="text",
                text=json.dumps(self._compact_record(cve_record), indent=2),
            )
        ]

    @staticmethod
    def _validate_search(keyword: str, max_results: int) -> list[str]:
        """Validate cve_search arguments."""
        errors = []
        if not isinstance(keyword, str):
            errors.append("keyword must be a string")
        elif not (_MIN_KEYWORD_LEN <= len(keyword) <= _MAX_KEYWORD_LEN):
            errors.append(
                f"keyword must be {_MIN_KEYWORD_LEN}-{_MAX_KEYWORD_LEN} characters"
            )

        if not isinstance(max_results, int):
            errors.append("max_results must be an integer")
        elif not (1 <= max_results <= _MAX_RESULTS_CAP):
            errors.append(f"max_results must be 1-{_MAX_RESULTS_CAP}")

        return errors

    async def _call_nvd(self, params: dict[str, Any]) -> dict[str, Any]:
        """Make a request to the NVD API."""
        headers = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
            response = await client.get(NVD_API_BASE, params=params, headers=headers)
            response.raise_for_status()
            return response.json()

    @staticmethod
    def _compact_record(cve: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0912
        """Reduce a full NVD CVE record to the fields agents actually need.

        We deliberately strip CPE bindings, change history, and most metadata —
        the agent needs decision-supporting evidence, not raw NVD JSON.
        """
        cve_id = cve.get("id", "unknown")

        # Description (first English entry)
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        if len(description) > _TITLE_TRUNCATE:
            title = description[:_TITLE_TRUNCATE].rsplit(" ", 1)[0] + "..."
        else:
            title = description

        if len(description) > _DESCRIPTION_TRUNCATE:
            description_truncated = description[:_DESCRIPTION_TRUNCATE] + "..."
        else:
            description_truncated = description

        # CVSS v3 (prefer v3.1, fall back to v3.0)
        cvss_v3_score = None
        cvss_v3_severity = None
        cvss_v3_vector = None
        metrics = cve.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metric_entries = metrics.get(metric_key, [])
            if metric_entries:
                primary = metric_entries[0]
                cvss_data = primary.get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                cvss_v3_severity = cvss_data.get("baseSeverity")
                cvss_v3_vector = cvss_data.get("vectorString")
                break

        # CWE IDs from weaknesses
        cwe_ids: list[str] = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                value = desc.get("value", "")
                if value.startswith("CWE-") and value not in cwe_ids:
                    cwe_ids.append(value)

        # Top references (up to 3)
        references: list[str] = []
        for ref in cve.get("references", [])[:_MAX_REFERENCES_RETURNED]:
            url = ref.get("url")
            if url:
                references.append(url)

        return {
            "cve_id": cve_id,
            "title": title,
            "description": description_truncated,
            "cvss_v3_score": cvss_v3_score,
            "cvss_v3_severity": cvss_v3_severity,
            "cvss_v3_vector": cvss_v3_vector,
            "cwe_ids": cwe_ids,
            "published_date": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "references": references,
        }

    async def run(self) -> None:
        """Start the MCP server and handle requests."""
        _log.info("CVE MCP server running")
        async with stdio_server() as (read_stream, write_stream):
            await self._server.run(
                read_stream,
                write_stream,
                self._server.create_initialization_options(),
            )


def _error_response(message: str) -> list[TextContent]:
    """Build a standard error response."""
    return [
        TextContent(
            type="text",
            text=json.dumps({"error": message, "success": False}, indent=2),
        )
    ]

async def main() -> None:
    """Entry point for the CVE MCP server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    server = CVEServer()
    await server.run()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())

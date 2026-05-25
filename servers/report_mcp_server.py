"""Report MCP server: draft_finding tool for structured vulnerability findings.

Exposes ``draft_finding`` (and ``write_finding`` as an alias). Accepts
structured vulnerability evidence and validates it against a schema
before recording. All findings are written to a findings artifact
(JSONL format, one per line) with a UUID and timestamp.

The schema mirrors the vocabulary the LLM naturally produces during
the Report phase — evidence as a list, severity as a CVSS string,
remediation_guidance as a list, standards_mapping as a list of CWE
identifiers. This means the framework meets the model where it lives
rather than forcing it to learn invented field names.

The server enforces structure; the agent cannot emit free-form findings.
This aligns with Pathfinder's governance-first design: the tool itself
is the policy mechanism.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

_log = logging.getLogger(__name__)

# Pattern for CWE identifiers as accepted in standards_mapping entries.
_CWE_PATTERN = re.compile(r"^CWE-\d+$")

# In-memory dedup set for the current server session. Tracks normalised
# finding titles to reject duplicates structurally rather than relying
# on prompt-only dedup hints. Reset when the server process restarts
# (i.e. once per engagement).
_written_titles: set[str] = set()

# Schema for a valid finding. Matches the vocabulary the LLM naturally
# emits during the Report phase.
FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {
            "type": "string",
            "description": "Short title of the vulnerability",
            "minLength": 1,
            "maxLength": 200,
        },
        "description": {
            "type": "string",
            "description": "Detailed description of the vulnerability",
            "minLength": 1,
            "maxLength": 2000,
        },
        "evidence": {
            "type": "array",
            "description": (
                "List of evidence statements observed during validation "
                "(e.g., 'Successful login with default credentials')."
            ),
            "items": {"type": "string", "minLength": 1},
            "minItems": 1,
        },
        "severity": {
            "type": "string",
            "description": (
                "Severity rating, ideally including a CVSS v3.1 score "
                "(e.g., 'High (CVSS v3.1: 8.2)' or 'Critical (CVSS 9.8)')."
            ),
            "minLength": 1,
            "maxLength": 200,
        },
        "affected_assets": {
            "type": "array",
            "description": "List of affected hosts, services, or components",
            "items": {"type": "string", "minLength": 1},
            "minItems": 1,
        },
        "remediation_guidance": {
            "type": "array",
            "description": "Ordered list of recommended remediation steps",
            "items": {"type": "string", "minLength": 1},
            "minItems": 1,
        },
        "standards_mapping": {
            "type": "array",
            "description": (
                "List of standards or framework references (e.g., 'CWE-798', "
                "'CWE-250'). Each CWE entry must match the pattern CWE-NNNN."
            ),
            "items": {"type": "string", "minLength": 1},
            "minItems": 1,
        },
        "vulnerability_id": {
            "type": "integer",
            "description": (
                "Optional sequential or engagement-local identifier for "
                "cross-referencing within the report."
            ),
        },
    },
    "required": [
        "title",
        "description",
        "evidence",
        "severity",
        "affected_assets",
        "remediation_guidance",
        "standards_mapping",
    ],
    "additionalProperties": False,
}

# Output directory for findings
FINDINGS_DIR = Path(__file__).parent.parent.parent / "runs" / "findings"

# Constants for validation
_MIN_LEN = 1
_MAX_TITLE = 200
_MAX_DESCRIPTION = 2000
_MAX_SEVERITY = 200


class ReportServer:
    """MCP server for report-phase tools."""

    def __init__(self, findings_dir: Path | None = None) -> None:
        self._server = Server("report-mcp-server")
        self._findings_dir = findings_dir or FINDINGS_DIR
        self._findings_dir.mkdir(parents=True, exist_ok=True)

        @self._server.list_tools()
        async def list_tools() -> list[Tool]:
            return self.get_tool_definitions()

        @self._server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
            if name not in {"draft_finding", "write_finding"}:
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(
                            {"error": f"Unknown tool: {name}", "written": False},
                            indent=2,
                        ),
                    )
                ]

            return await self._handle_draft_finding(**arguments)

    def get_tool_definitions(self) -> list[Tool]:
        """Return the list of tools exposed by this server.

        Both ``draft_finding`` and ``write_finding`` are exposed with the
        same schema. ``draft_finding`` is the primary name (what the LLM
        naturally picks); ``write_finding`` is kept as an alias.
        """
        description = (
            "Write a structured vulnerability finding to the findings log. "
            "Required fields: title, description, evidence (list), severity "
            "(string with CVSS), affected_assets (list), remediation_guidance "
            "(list), standards_mapping (list, CWE entries must match CWE-NNNN). "
            "Each finding is recorded with a UUID and timestamp."
        )
        return [
            Tool(
                name="draft_finding",
                description=description,
                inputSchema=FINDING_SCHEMA,
            ),
            Tool(
                name="write_finding",
                description=description + " (Alias of draft_finding.)",
                inputSchema=FINDING_SCHEMA,
            ),
        ]

    @staticmethod
    async def _handle_draft_finding(**kwargs: Any) -> list[TextContent]:
        """Handle the draft_finding (or write_finding) tool call.

        Validates all arguments against FINDING_SCHEMA, checks for
        duplicate titles, then writes the finding to the findings artifact.
        """
        errors = ReportServer._validate_finding(kwargs)
        if errors:
            error_msg = "; ".join(errors)
            _log.warning("draft_finding validation failed: %s", error_msg)
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {"error": error_msg, "written": False},
                        indent=2,
                    ),
                )
            ]

        # Structural dedup check — reject findings with titles already
        # written in this engagement session. Uses the module-level
        # _written_titles set which persists for the server's lifetime
        # (one engagement run).
        title = kwargs.get("title", "")
        normalised_title = title.strip().lower()
        if normalised_title in _written_titles:
            msg = (
                f"Duplicate finding rejected: a finding with title "
                f"'{title}' has already been written in this engagement. "
                f"Review prior iterations before drafting."
            )
            _log.info("Dedup rejected: %s", title)
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {"error": msg, "written": False},
                        indent=2,
                    ),
                )
            ]
        _written_titles.add(normalised_title)

        try:
            finding_id = str(uuid4())
            finding_record = {
                "finding_id": finding_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "finding": kwargs,
            }
            line = json.dumps(finding_record, separators=(",", ":"))
            findings_file = FINDINGS_DIR / "findings.jsonl"
            with findings_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            _log.info(
                "Finding written: %s (%s)", kwargs.get("title"), finding_id
            )
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {"finding_id": finding_id, "written": True},
                        indent=2,
                    ),
                )
            ]
        except Exception as exc:
            _log.exception("Failed to write finding")
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "error": f"Write failed: {exc}",
                            "written": False,
                        },
                        indent=2,
                    ),
                )
            ]

    @staticmethod
    def _validate_finding(args: dict[str, Any]) -> list[str]:  # noqa: PLR0912
        """Validate a finding against FINDING_SCHEMA.

        Returns a list of error messages. Empty list means valid.
        """
        errors = []

        # Required / unexpected fields
        required = set(FINDING_SCHEMA["required"])
        provided = set(args.keys())
        missing = required - provided
        if missing:
            errors.append(
                f"Missing required fields: {', '.join(sorted(missing))}"
            )

        allowed = set(FINDING_SCHEMA["properties"].keys())
        unexpected = provided - allowed
        if unexpected:
            errors.append(
                f"Unexpected fields (additionalProperties=false): "
                f"{', '.join(sorted(unexpected))}"
            )

        # Field-level validation
        if "title" in args:
            errors.extend(_check_string(args["title"], "title", 1, _MAX_TITLE))

        if "description" in args:
            errors.extend(
                _check_string(
                    args["description"], "description", 1, _MAX_DESCRIPTION
                )
            )

        if "severity" in args:
            errors.extend(
                _check_string(args["severity"], "severity", 1, _MAX_SEVERITY)
            )

        if "evidence" in args:
            errors.extend(_check_string_list(args["evidence"], "evidence"))

        if "affected_assets" in args:
            errors.extend(
                _check_string_list(args["affected_assets"], "affected_assets")
            )

        if "remediation_guidance" in args:
            errors.extend(
                _check_string_list(
                    args["remediation_guidance"], "remediation_guidance"
                )
            )

        if "standards_mapping" in args:
            mapping = args["standards_mapping"]
            errors.extend(_check_string_list(mapping, "standards_mapping"))
            # If structurally a non-empty list of strings, also check that any
            # CWE-looking entries are well-formed.
            if isinstance(mapping, list):
                for item in mapping:
                    if (
                        isinstance(item, str)
                        and item.upper().startswith("CWE")
                        and not _CWE_PATTERN.match(item)
                    ):
                        errors.append(
                            f"standards_mapping entry '{item}' looks like a "
                            "CWE reference but does not match the format "
                            "CWE-NNNN"
                        )

        if "vulnerability_id" in args and not isinstance(
            args["vulnerability_id"], int
        ):
            errors.append("vulnerability_id must be an integer")

        return errors

    async def run(self) -> None:
        """Start the MCP server and handle requests."""
        _log.info("Report MCP server running")
        async with stdio_server() as (read_stream, write_stream):
            await self._server.run(
                read_stream,
                write_stream,
                self._server.create_initialization_options(),
            )


# ---- Helpers ----------------------------------------------------------------


def _check_string(
    value: Any, name: str, min_len: int, max_len: int
) -> list[str]:
    """Validate a single string field. Returns a list of error messages."""
    if not isinstance(value, str):
        return [f"{name} must be a string"]
    if not (min_len <= len(value) <= max_len):
        return [f"{name} must be {min_len}-{max_len} characters"]
    return []


def _check_string_list(value: Any, name: str) -> list[str]:
    """Validate a non-empty array of non-empty strings."""
    if not isinstance(value, list):
        return [f"{name} must be an array"]
    if len(value) < _MIN_LEN:
        return [f"{name} must have at least 1 item"]
    if not all(isinstance(s, str) and s.strip() for s in value):
        return [f"all {name} items must be non-empty strings"]
    return []


async def main() -> None:
    """Entry point for the report MCP server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    server = ReportServer()
    await server.run()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())

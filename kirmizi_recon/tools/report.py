"""The ``finalize_report`` tool — how Claude ends the run with structured output.

Its ``input_schema`` is derived (strict) from ``ReconFindingsPayload`` so the
model must emit a fully-formed, validated report. The agent loop treats a call
to this tool as the terminal step.
"""

from __future__ import annotations

from typing import Any

from ..schemas import ReconFindingsPayload, strict_tool_schema

FINALIZE_TOOL_NAME = "finalize_report"

FINALIZE_TOOL: dict[str, Any] = {
    "name": FINALIZE_TOOL_NAME,
    "description": (
        "Emit the final structured reconnaissance report and end the run. Call "
        "this exactly once, after you have gathered and analyzed enough evidence. "
        "Populate every field: summarize infrastructure and AI-application "
        "findings, list concrete findings with severity/confidence/evidence, "
        "describe the attack surface, and recommend next steps for a downstream "
        "attack-planning agent. Base every claim on evidence you actually "
        "collected via the other tools."
    ),
    "strict": True,
    "input_schema": strict_tool_schema(ReconFindingsPayload),
}


def parse_finalize(tool_input: dict[str, Any]) -> ReconFindingsPayload:
    """Validate the model's finalize payload into a ReconFindingsPayload."""
    return ReconFindingsPayload.model_validate(tool_input)

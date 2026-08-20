"""Pydantic schemas — the stable contract between the recon agent and its callers.

`ReconTarget` (in) and `ReconReport` (out) are the interface-agnostic boundary:
the CLI uses them today, and a future A2A server maps an incoming message to a
`ReconTarget` and serializes the `ReconReport` as an artifact — no refactor
needed.

The strict tool schema used to force structured output from Claude is derived
from `ReconFindingsPayload` via `strict_tool_schema()`. That payload avoids
`Optional`/`default` and numeric/string constraints so it satisfies the
structured-output limitations (all properties required, additionalProperties
false, no min/max constraints).
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

Mode = Literal["passive", "active"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


class AITargetEndpoint(BaseModel):
    """A target AI endpoint to probe. Deliberately generic so the agent can talk
    to any provider: the probe prompt is substituted into ``request_template``
    (JSON with a ``{prompt}`` placeholder), and ``response_path`` is a
    dotted/bracket path into the JSON response used to extract the reply text.
    """

    url: str
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    # e.g. '{"model": "gpt-x", "messages": [{"role": "user", "content": {prompt}}]}'
    request_template: str = '{"messages": [{"role": "user", "content": {prompt}}]}'
    # Dotted path into the JSON response, e.g. "choices.0.message.content".
    response_path: str = "choices.0.message.content"
    label: str = ""


class ReconTarget(BaseModel):
    """What to run reconnaissance on. Hybrid: domains/hosts (infrastructure) and
    AI endpoints (the application)."""

    name: str = "target"
    domains: list[str] = Field(default_factory=list)
    ai_endpoints: list[AITargetEndpoint] = Field(default_factory=list)
    objective: str = (
        "Perform hybrid reconnaissance on the target: fingerprint the AI "
        "application and map the surrounding infrastructure/attack surface."
    )

    @model_validator(mode="after")
    def _require_something(self) -> "ReconTarget":
        if not self.domains and not self.ai_endpoints:
            raise ValueError("ReconTarget needs at least one domain or ai_endpoint.")
        return self


class ReconScope(BaseModel):
    """Authorization + safety envelope. Enforced fail-closed by ``scope.py``."""

    mode: Mode = "passive"
    in_scope: list[str] = Field(
        default_factory=list,
        description="Host/domain patterns authorized for probing. Supports a "
        "leading '*.' wildcard, e.g. '*.acme.example.com'.",
    )
    ai_endpoints: list[str] = Field(
        default_factory=list,
        description="Exact target AI endpoint URLs authorized for active probing.",
    )
    authorization: str = Field(
        default="",
        description="Engagement/SOW reference. Mandatory (non-empty) for active "
        "mode unless trust_local is set.",
    )
    max_active_requests: int = 200
    rate_limit_per_sec: float = 2.0
    trust_local: bool = Field(
        default=False,
        description="Permit active probing of localhost / RFC-1918 targets you "
        "own without a full authorization reference.",
    )

    @model_validator(mode="after")
    def _active_needs_authorization(self) -> "ReconScope":
        if self.mode == "active" and not self.trust_local and not self.authorization.strip():
            raise ValueError(
                "Active mode requires a non-empty 'authorization' (engagement/SOW "
                "reference), or --trust-local for local targets you own."
            )
        return self


# ---------------------------------------------------------------------------
# Deterministic collection output (the analyst phase consumes this)
# ---------------------------------------------------------------------------


class Evidence(BaseModel):
    """Raw results from the deterministic collection phase, keyed by target.
    This is the seam between collect() (no LLM) and analyze() (agentic) — and,
    in a future multi-agent setup, between a collector agent and an analyst
    agent over A2A."""

    dns: dict[str, Any] = Field(default_factory=dict)
    subdomains: dict[str, Any] = Field(default_factory=dict)
    rdap: dict[str, Any] = Field(default_factory=dict)
    port_scan: dict[str, Any] = Field(default_factory=dict)
    http: dict[str, Any] = Field(default_factory=dict)
    tls: dict[str, Any] = Field(default_factory=dict)
    endpoints: dict[str, Any] = Field(default_factory=dict)
    collection_log: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    def to_prompt_json(self) -> str:
        return self.model_dump_json(indent=2)


# ---------------------------------------------------------------------------
# Output — findings payload (Claude fills this via the finalize_report tool)
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    title: str = ""
    category: Literal["infra", "ai", "osint"] = "infra"
    severity: Severity = "info"
    confidence: Confidence = "low"
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    recommendation: str = ""


class InfraFindings(BaseModel):
    subdomains: list[str] = Field(default_factory=list)
    dns_records: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    tls: list[str] = Field(default_factory=list)
    open_services: list[str] = Field(default_factory=list)
    notes: str = ""


class AIFindings(BaseModel):
    suspected_model: str = ""
    model_confidence: Confidence = "low"
    guardrails_observed: list[str] = Field(default_factory=list)
    refusal_behavior: str = ""
    prompt_leak_indicators: list[str] = Field(default_factory=list)
    exposed_tools: list[str] = Field(default_factory=list)
    injection_surface: list[str] = Field(default_factory=list)
    notes: str = ""


class ReconFindingsPayload(BaseModel):
    """The analysis Claude produces. Kept free of Optional/constraints so the
    derived strict-tool schema is valid for structured output."""

    objective_summary: str = ""
    infra: InfraFindings = Field(default_factory=InfraFindings)
    ai: AIFindings = Field(default_factory=AIFindings)
    findings: list[Finding] = Field(default_factory=list)
    attack_surface_summary: str = ""
    recommended_next_steps: list[str] = Field(default_factory=list)
    overall_confidence: Confidence = "low"


# ---------------------------------------------------------------------------
# Output — full report (payload + run metadata we attach ourselves)
# ---------------------------------------------------------------------------


class ReconReport(BaseModel):
    target_name: str
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    scope_mode: Mode = "passive"
    authorization_ref: str = ""
    objective: str = ""

    # Analysis (from ReconFindingsPayload)
    objective_summary: str = ""
    infra: InfraFindings = Field(default_factory=InfraFindings)
    ai: AIFindings = Field(default_factory=AIFindings)
    findings: list[Finding] = Field(default_factory=list)
    attack_surface_summary: str = ""
    recommended_next_steps: list[str] = Field(default_factory=list)
    overall_confidence: Confidence = "low"

    # Run metadata
    evidence_log: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @classmethod
    def from_payload(
        cls,
        payload: ReconFindingsPayload,
        *,
        target: ReconTarget,
        scope: ReconScope,
        evidence_log: list[str] | None = None,
        errors: list[str] | None = None,
    ) -> "ReconReport":
        return cls(
            target_name=target.name,
            scope_mode=scope.mode,
            authorization_ref=scope.authorization,
            objective=target.objective,
            objective_summary=payload.objective_summary,
            infra=payload.infra,
            ai=payload.ai,
            findings=payload.findings,
            attack_surface_summary=payload.attack_surface_summary,
            recommended_next_steps=payload.recommended_next_steps,
            overall_confidence=payload.overall_confidence,
            evidence_log=evidence_log or [],
            errors=errors or [],
        )


# ---------------------------------------------------------------------------
# Strict-tool schema derivation
# ---------------------------------------------------------------------------

_DROP_KEYS = {
    "title",
    "default",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "minItems",
    "maxItems",
    "pattern",
}


def _harden(node: Any) -> Any:
    """Recursively adapt a Pydantic JSON schema for strict tool use: drop
    unsupported constraint keywords, force additionalProperties:false on every
    object, and mark every property required."""
    if isinstance(node, list):
        return [_harden(n) for n in node]
    if not isinstance(node, dict):
        return node

    out: dict[str, Any] = {}
    for key, value in node.items():
        if key in _DROP_KEYS:
            continue
        out[key] = _harden(value)

    if out.get("type") == "object" or "properties" in out:
        out["additionalProperties"] = False
        props = out.get("properties")
        if isinstance(props, dict):
            out["required"] = list(props.keys())
    return out


def strict_tool_schema(model: type[BaseModel]) -> dict[str, Any]:
    """Return a strict-tool-compatible ``input_schema`` for a Pydantic model."""
    raw = model.model_json_schema()
    return _harden(copy.deepcopy(raw))

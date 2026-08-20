"""ReconAgent — the interface-agnostic core.

``run(target, scope) -> ReconReport`` drives a manual agentic loop over Claude
(chosen over the tool runner so we own scope enforcement, active-action gating,
rate limiting, and pause_turn resumption). The CLI calls it today; a future A2A
AgentExecutor can wrap the same method unchanged.
"""

from __future__ import annotations

from typing import Any

import anthropic

from . import collector
from .config import Settings
from .prompts import build_analysis_kickoff, build_system_prompt
from .schemas import Evidence, ReconReport, ReconScope, ReconTarget
from .scope import ScopeEnforcer
from .tools import ToolRegistry
from .tools.report import FINALIZE_TOOL_NAME, parse_finalize

_WEB_TOOLS: list[dict[str, Any]] = [
    {"type": "web_search_20260209", "name": "web_search"},
    {"type": "web_fetch_20260209", "name": "web_fetch"},
]


class ReconAgent:
    def __init__(
        self,
        settings: Settings | None = None,
        client: anthropic.Anthropic | None = None,
    ) -> None:
        self.settings = settings or Settings.from_env()
        self.client = client or anthropic.Anthropic()

    def run(self, target: ReconTarget, scope: ReconScope) -> ReconReport:
        """Full recon: deterministic collection, then agentic analysis."""
        registry = ToolRegistry(target, ScopeEnforcer(scope))
        evidence = collector.collect(target, scope, registry)
        return self.analyze(target, scope, evidence, registry=registry)

    def collect(self, target: ReconTarget, scope: ReconScope) -> Evidence:
        """Deterministic collection phase only — no LLM, no API key required."""
        registry = ToolRegistry(target, ScopeEnforcer(scope))
        return collector.collect(target, scope, registry)

    def analyze(
        self,
        target: ReconTarget,
        scope: ReconScope,
        evidence: Evidence,
        registry: ToolRegistry | None = None,
    ) -> ReconReport:
        """Agentic analysis phase: interpret pre-collected evidence, probe the AI
        app adaptively, run targeted follow-ups, and synthesize the report."""
        if registry is None:
            registry = ToolRegistry(target, ScopeEnforcer(scope))
        system_prompt = build_system_prompt(target, scope)
        extra = _WEB_TOOLS if self.settings.enable_web else None
        tools = registry.tool_definitions(extra=extra)

        messages: list[dict[str, Any]] = [
            {"role": "user", "content": build_analysis_kickoff(target, evidence)}
        ]
        errors: list[str] = list(evidence.errors)
        nudges = 0

        for _turn in range(self.settings.max_turns):
            try:
                resp = self._create(system_prompt, tools, messages)
            except (anthropic.AnthropicError, TypeError) as exc:
                # Covers API errors and setup errors — notably the SDK's
                # TypeError when no credentials can be resolved.
                errors.append(f"API error: {type(exc).__name__}: {exc}")
                break

            if resp.stop_reason == "refusal":
                cat = getattr(getattr(resp, "stop_details", None), "category", None)
                errors.append(f"model refused (category={cat}); run halted.")
                break

            messages.append({"role": "assistant", "content": resp.content})

            if resp.stop_reason == "pause_turn":
                # Server-tool turn paused; re-send to resume.
                continue

            tool_uses = [b for b in resp.content if getattr(b, "type", None) == "tool_use"]

            finalize = next(
                (b for b in tool_uses if b.name == FINALIZE_TOOL_NAME), None
            )
            if finalize is not None:
                try:
                    payload = parse_finalize(dict(finalize.input))
                except Exception as exc:
                    errors.append(f"finalize_report payload invalid: {exc}")
                    break
                return ReconReport.from_payload(
                    payload,
                    target=target,
                    scope=scope,
                    evidence_log=registry.evidence_log,
                    errors=errors,
                )

            if not tool_uses:
                # Model ended without finalizing — nudge, then give up.
                if resp.stop_reason == "end_turn" and nudges < 2:
                    nudges += 1
                    messages.append(
                        {
                            "role": "user",
                            "content": "Call finalize_report now with the "
                            "findings you have gathered.",
                        }
                    )
                    continue
                errors.append("model stopped without calling finalize_report.")
                break

            results = []
            for tu in tool_uses:
                content, is_error = registry.dispatch(tu.name, dict(tu.input))
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tu.id,
                        "content": content,
                        "is_error": is_error,
                    }
                )
            messages.append({"role": "user", "content": results})
        else:
            errors.append(f"reached max_turns ({self.settings.max_turns}) without a report.")

        # No structured report produced — return a metadata-only report so the
        # caller still gets evidence + errors rather than nothing.
        return ReconReport(
            target_name=target.name,
            scope_mode=scope.mode,
            authorization_ref=scope.authorization,
            objective=target.objective,
            objective_summary="Run ended without a finalized report.",
            evidence_log=registry.evidence_log,
            errors=errors,
        )

    # -- request construction -------------------------------------------
    def _create(
        self,
        system_prompt: str,
        tools: list[dict[str, Any]],
        messages: list[dict[str, Any]],
    ):
        kwargs: dict[str, Any] = dict(
            model=self.settings.model,
            max_tokens=self.settings.max_tokens,
            system=[
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            tools=tools,
            output_config={"effort": self.settings.effort},
            messages=messages,
        )
        if self.settings.use_fallbacks:
            try:
                return self.client.beta.messages.create(
                    **kwargs,
                    betas=[self.settings.fallback_beta],
                    fallbacks="default",
                )
            except (anthropic.BadRequestError, TypeError):
                # Environment doesn't support server-side fallbacks — degrade.
                self.settings.use_fallbacks = False
        return self.client.messages.create(**kwargs)

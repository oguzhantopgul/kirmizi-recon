"""Render a ReconReport to JSON and Markdown."""

from __future__ import annotations

from .schemas import ReconReport


def to_json(report: ReconReport, *, indent: int = 2) -> str:
    return report.model_dump_json(indent=indent)


def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {i}" for i in items) if items else "_(none)_"


def to_markdown(report: ReconReport) -> str:
    r = report
    lines: list[str] = []
    lines.append(f"# Recon Report — {r.target_name}")
    lines.append("")
    lines.append(f"- **Generated:** {r.generated_at}")
    lines.append(f"- **Mode:** {r.scope_mode}")
    lines.append(f"- **Authorization:** {r.authorization_ref or '(none)'}")
    lines.append(f"- **Overall confidence:** {r.overall_confidence}")
    lines.append("")
    lines.append(f"**Objective:** {r.objective}")
    lines.append("")
    if r.objective_summary:
        lines.append("## Summary")
        lines.append(r.objective_summary)
        lines.append("")

    lines.append("## Attack surface")
    lines.append(r.attack_surface_summary or "_(none)_")
    lines.append("")

    lines.append("## Infrastructure")
    lines.append(f"**Subdomains:**\n{_bullets(r.infra.subdomains)}")
    lines.append(f"\n**DNS records:**\n{_bullets(r.infra.dns_records)}")
    lines.append(f"\n**Technologies:**\n{_bullets(r.infra.technologies)}")
    lines.append(f"\n**TLS:**\n{_bullets(r.infra.tls)}")
    lines.append(f"\n**Open services:**\n{_bullets(r.infra.open_services)}")
    if r.infra.notes:
        lines.append(f"\n{r.infra.notes}")
    lines.append("")

    lines.append("## AI application")
    lines.append(f"- **Suspected model:** {r.ai.suspected_model or '(unknown)'} "
                 f"(confidence: {r.ai.model_confidence})")
    lines.append(f"- **Refusal behavior:** {r.ai.refusal_behavior or '(not observed)'}")
    lines.append(f"\n**Guardrails observed:**\n{_bullets(r.ai.guardrails_observed)}")
    lines.append(f"\n**Prompt-leak indicators:**\n{_bullets(r.ai.prompt_leak_indicators)}")
    lines.append(f"\n**Exposed tools:**\n{_bullets(r.ai.exposed_tools)}")
    lines.append(f"\n**Injection surface:**\n{_bullets(r.ai.injection_surface)}")
    if r.ai.notes:
        lines.append(f"\n{r.ai.notes}")
    lines.append("")

    lines.append("## Findings")
    if r.findings:
        for f in r.findings:
            lines.append(
                f"### [{f.severity.upper()}] {f.title}  "
                f"_(category: {f.category}, confidence: {f.confidence})_"
            )
            if f.description:
                lines.append(f.description)
            if f.evidence:
                lines.append(f"\n**Evidence:**\n{_bullets(f.evidence)}")
            if f.recommendation:
                lines.append(f"\n**Recommendation:** {f.recommendation}")
            lines.append("")
    else:
        lines.append("_(none)_")
        lines.append("")

    lines.append("## Recommended next steps (for downstream attack agent)")
    lines.append(_bullets(r.recommended_next_steps))
    lines.append("")

    lines.append("## Evidence log")
    lines.append(_bullets(r.evidence_log))
    lines.append("")

    if r.errors:
        lines.append("## Errors / notes")
        lines.append(_bullets(r.errors))
        lines.append("")

    return "\n".join(lines)

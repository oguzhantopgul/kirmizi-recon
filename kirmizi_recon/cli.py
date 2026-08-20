"""Command-line interface for kirmizi-recon.

The CLI is a thin shell over ``ReconAgent.run``. It assembles a ``ReconTarget``
and ``ReconScope`` from flags and/or an engagement (scope) file, runs the agent,
and renders the report. The same core is what a future A2A server would wrap.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

import typer

from .config import Settings
from .report import to_json, to_markdown
from .schemas import AITargetEndpoint, ReconScope, ReconTarget
from .scope import host_from_url

app = typer.Typer(add_completion=False, help="AI Red Teaming Recon Agent.")


def _load_engagement(path: Optional[str]) -> dict:
    path = path or os.getenv("KIRMIZI_ENGAGEMENT")
    if not path:
        return {}
    import yaml

    data = yaml.safe_load(Path(path).read_text()) or {}
    if not isinstance(data, dict):
        raise typer.BadParameter(f"engagement file {path} must be a YAML mapping")
    return data


def _build_endpoints(eng_target: dict, cli_endpoints: list[str]) -> list[AITargetEndpoint]:
    endpoints: dict[str, AITargetEndpoint] = {}
    for raw in eng_target.get("ai_endpoints", []) or []:
        if isinstance(raw, str):
            endpoints[raw] = AITargetEndpoint(url=raw)
        elif isinstance(raw, dict) and raw.get("url"):
            endpoints[raw["url"]] = AITargetEndpoint(**raw)
    for url in cli_endpoints or []:
        endpoints.setdefault(url, AITargetEndpoint(url=url))
    return list(endpoints.values())


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    domain: list[str] = typer.Option(
        [], "--domain", "-d", help="Target domain/host (repeatable)."
    ),
    ai_endpoint: list[str] = typer.Option(
        [], "--ai-endpoint", "-e", help="Target AI endpoint URL (repeatable)."
    ),
    name: Optional[str] = typer.Option(None, "--name", help="Label for the target."),
    objective: Optional[str] = typer.Option(None, "--objective", help="Recon focus."),
    active: Optional[bool] = typer.Option(
        None, "--active/--passive", help="Enable active probing (gated by scope). "
        "Defaults to the engagement file's mode, else passive."
    ),
    engagement: Optional[str] = typer.Option(
        None, "--engagement", "--scope-file", help="Engagement/scope YAML file "
        "(default: $KIRMIZI_ENGAGEMENT)."
    ),
    in_scope: list[str] = typer.Option(
        [], "--in-scope", help="Authorized target for active probing (repeatable): "
        "a host/domain ('*.domain' wildcard ok), a bare IP, or a CIDR "
        "(e.g. 203.0.113.0/24)."
    ),
    authorization: Optional[str] = typer.Option(
        None, "--authorization", "--auth", help="Engagement/SOW reference "
        "(required for active mode)."
    ),
    trust_local: bool = typer.Option(
        False, "--trust-local", help="Allow active probing of local targets you own."
    ),
    rate: Optional[float] = typer.Option(None, "--rate", help="Active requests/sec."),
    max_active: Optional[int] = typer.Option(None, "--max-active", help="Active-request budget."),
    effort: Optional[str] = typer.Option(None, "--effort", help="low|medium|high|xhigh|max."),
    max_turns: Optional[int] = typer.Option(None, "--max-turns", help="Agent loop cap."),
    no_web: bool = typer.Option(False, "--no-web", help="Disable server-side web search/fetch."),
    collect_only: bool = typer.Option(
        False, "--collect-only", help="Run only the deterministic collection phase "
        "(no LLM, no API key) and output the raw evidence."
    ),
    out: Optional[str] = typer.Option(None, "--out", help="Write <out>.recon.json and .md."),
    quiet: bool = typer.Option(False, "--quiet", help="Don't print the report to stdout."),
) -> None:
    """Run reconnaissance against a target and emit a structured report."""
    if ctx.invoked_subcommand is not None:
        return

    eng = _load_engagement(engagement)
    eng_target = eng.get("target", {}) if isinstance(eng.get("target"), dict) else {}

    domains = list(domain) or list(eng_target.get("domains", []) or [])
    endpoints = _build_endpoints(eng_target, list(ai_endpoint))

    if not domains and not endpoints:
        raise typer.BadParameter(
            "provide at least one --domain or --ai-endpoint (or a target in the "
            "engagement file)."
        )

    target = ReconTarget(
        name=name or eng_target.get("name", "target"),
        domains=domains,
        ai_endpoints=endpoints,
        objective=objective or eng_target.get("objective") or ReconTarget.model_fields["objective"].default,
    )

    # Scope: an explicit --active/--passive flag overrides the engagement file.
    if active is None:
        mode = eng.get("mode", "passive")
    else:
        mode = "active" if active else "passive"

    scope_in = list(in_scope) or list(eng.get("in_scope", []) or [])
    if not scope_in:
        # Naming a target authorizes it; the authorization field is the real gate.
        scope_in = list(domains)
        scope_in += [host_from_url(e.url) for e in endpoints]
        scope_in = sorted({s for s in scope_in if s})

    scope_ai = list(eng.get("ai_endpoints", []) or [])
    scope_ai += [e.url for e in endpoints]
    scope_ai = sorted(set(scope_ai))

    try:
        scope = ReconScope(
            mode=mode,
            in_scope=scope_in,
            ai_endpoints=scope_ai,
            authorization=authorization if authorization is not None else eng.get("authorization", ""),
            max_active_requests=max_active if max_active is not None else eng.get("max_active_requests", 200),
            rate_limit_per_sec=rate if rate is not None else eng.get("rate_limit_per_sec", 2.0),
            trust_local=trust_local or bool(eng.get("trust_local", False)),
        )
    except ValueError as exc:
        typer.secho(f"scope error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    # Deterministic collection only — no LLM, no API key.
    if collect_only:
        from . import collector
        from .scope import ScopeEnforcer
        from .tools import ToolRegistry

        typer.secho(
            f"[kirmizi-recon] collect-only mode={scope.mode} target={target.name}",
            fg=typer.colors.CYAN,
            err=True,
        )
        registry = ToolRegistry(target, ScopeEnforcer(scope))
        evidence = collector.collect(target, scope, registry)
        payload = evidence.to_prompt_json()
        if out:
            Path(f"{out}.evidence.json").write_text(payload)
            typer.secho(f"wrote {out}.evidence.json", fg=typer.colors.GREEN, err=True)
        if not quiet:
            sys.stdout.write(payload + "\n")
        raise typer.Exit(code=0)

    settings = Settings.from_env()
    if effort:
        settings.effort = effort
    if max_turns is not None:
        settings.max_turns = max_turns
    if no_web:
        settings.enable_web = False

    # Import the agent lazily so `--help` and arg errors don't require the SDK/key.
    try:
        from .agent import ReconAgent

        agent = ReconAgent(settings=settings)
    except Exception as exc:  # e.g. missing API key/credentials
        typer.secho(
            f"could not initialize the agent: {exc}\n"
            "Set ANTHROPIC_API_KEY or run `ant auth login`.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    typer.secho(
        f"[kirmizi-recon] mode={scope.mode} target={target.name} "
        f"domains={len(domains)} ai_endpoints={len(endpoints)}",
        fg=typer.colors.CYAN,
        err=True,
    )

    report = agent.run(target, scope)

    if any(
        s in e.lower()
        for e in report.errors
        for s in ("could not resolve authentication", "api_key", "authentication")
    ):
        typer.secho(
            "No Anthropic credentials resolved. Set ANTHROPIC_API_KEY or run "
            "`ant auth login`.",
            fg=typer.colors.RED,
            err=True,
        )

    if out:
        Path(f"{out}.recon.json").write_text(to_json(report))
        Path(f"{out}.recon.md").write_text(to_markdown(report))
        typer.secho(f"wrote {out}.recon.json and {out}.recon.md", fg=typer.colors.GREEN, err=True)

    if not quiet:
        try:
            from rich.console import Console
            from rich.markdown import Markdown

            Console().print(Markdown(to_markdown(report)))
        except Exception:
            sys.stdout.write(to_markdown(report) + "\n")


if __name__ == "__main__":  # pragma: no cover
    app()

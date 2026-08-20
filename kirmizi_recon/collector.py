"""Deterministic collection phase.

``collect()`` runs the broad, non-adaptive recon scans in plain code — no LLM
involved — producing a structured :class:`Evidence` bundle. It calls the same
``ToolRegistry.dispatch`` the agent uses, so scope enforcement, rate limiting,
and evidence logging are shared; the only thing that changes is *who decides
what to run* (fixed pipeline here, vs. the model in the agent loop).

Passive scans always run. Active scans (port/endpoint/HTTP/TLS) run only in
active mode; in passive mode the registry refuses them and they're recorded as
skipped. Adaptive `ai_probe` is deliberately NOT here — it belongs in the
agentic analyze phase.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from .schemas import Evidence, ReconScope, ReconTarget
from .scope import host_from_url


class _Dispatcher(Protocol):
    evidence_log: list[str]

    def dispatch(self, name: str, tool_input: dict[str, Any]) -> tuple[str, bool]: ...


def _run(registry: _Dispatcher, name: str, args: dict[str, Any]) -> Any:
    content, is_error = registry.dispatch(name, dict(args))
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        data = {"raw": content}
    if is_error:
        return {"skipped": True, "reason": content if isinstance(content, str) else data}
    return data


def _with_scheme(host: str) -> str:
    return host if "://" in host else "https://" + host


def _active_hosts(target: ReconTarget) -> list[str]:
    hosts: list[str] = list(target.domains)
    hosts += [host_from_url(e.url) for e in target.ai_endpoints]
    seen: set[str] = set()
    ordered: list[str] = []
    for h in hosts:
        h = h.strip()
        if h and h not in seen:
            seen.add(h)
            ordered.append(h)
    return ordered


def collect(target: ReconTarget, scope: ReconScope, registry: _Dispatcher) -> Evidence:
    """Run the deterministic scan pipeline and return an Evidence bundle."""
    ev = Evidence()

    # Passive — always.
    for domain in target.domains:
        ev.dns[domain] = _run(registry, "dns_lookup", {"domain": domain})
        ev.subdomains[domain] = _run(registry, "ct_subdomains", {"domain": domain})
        ev.rdap[domain] = _run(registry, "rdap_lookup", {"domain": domain})

    # Active — only in active mode (refused otherwise, recorded as skipped).
    if scope.mode == "active":
        for host in _active_hosts(target):
            ev.port_scan[host] = _run(
                registry, "port_scan", {"target": host, "ports": "top-100"}
            )
            ev.tls[host] = _run(registry, "tls_inspect", {"host": host})
            ev.http[host] = _run(registry, "http_fingerprint", {"url": _with_scheme(host)})
            ev.endpoints[host] = _run(
                registry, "endpoint_scan", {"base_url": _with_scheme(host)}
            )

    ev.collection_log = list(registry.evidence_log)
    return ev

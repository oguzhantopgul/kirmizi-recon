"""Tool registry: maps Claude tool definitions to callables, enforcing scope on
every active action and logging evidence.

Passive tools run unconditionally. Active tools consult the ScopeEnforcer first;
a refusal is returned to Claude as an error tool_result (not raised) so the run
continues and the agent adapts.
"""

from __future__ import annotations

import json
from typing import Any

from ..schemas import ReconTarget
from ..scope import ScopeEnforcer
from . import ai_target, infra
from .report import FINALIZE_TOOL, FINALIZE_TOOL_NAME

# name -> "passive" | "active"
TOOL_ACTIONS: dict[str, str] = {
    "dns_lookup": "passive",
    "ct_subdomains": "passive",
    "rdap_lookup": "passive",
    "http_fingerprint": "active",
    "tls_inspect": "active",
    "ai_probe": "active",
}

_GATHERER_DEFS: list[dict[str, Any]] = [
    {
        "name": "dns_lookup",
        "description": "Resolve A/AAAA/MX/TXT/NS/CNAME records for a domain. Passive.",
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    {
        "name": "ct_subdomains",
        "description": "Discover subdomains from certificate-transparency logs "
        "(crt.sh). Passive — queries a third party, not the target.",
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    {
        "name": "rdap_lookup",
        "description": "RDAP/WHOIS registration data for a domain (registrar, "
        "status, dates, nameservers). Passive.",
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    {
        "name": "http_fingerprint",
        "description": "Fetch a target URL: status, server/tech banners, security "
        "headers, cookies, page title, robots.txt. ACTIVE — sends requests to the "
        "target; requires the target to be in the authorized active scope.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "tls_inspect",
        "description": "Inspect the target's TLS certificate (subject, issuer, "
        "SANs, validity) and negotiated protocol/cipher. ACTIVE — performs a TLS "
        "handshake with the target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "ai_probe",
        "description": "Send one probe prompt to a configured target AI endpoint "
        "and return its raw response. Use a battery of these to fingerprint the "
        "model, map guardrails/refusals, detect system-prompt leakage, and find "
        "the prompt-injection surface. ACTIVE — sends a request to the target AI.",
        "input_schema": {
            "type": "object",
            "properties": {
                "endpoint_url": {
                    "type": "string",
                    "description": "URL of a target AI endpoint configured on the "
                    "target. If only one is configured, it is used by default.",
                },
                "prompt": {"type": "string"},
            },
            "required": ["prompt"],
        },
    },
]


class ToolRegistry:
    def __init__(self, target: ReconTarget, enforcer: ScopeEnforcer) -> None:
        self.target = target
        self.enforcer = enforcer
        self.evidence_log: list[str] = []

    # -- tool definitions handed to Claude -------------------------------
    def tool_definitions(
        self, extra: list[dict[str, Any]] | None = None
    ) -> list[dict[str, Any]]:
        """Client gatherer tools + any server tools (e.g. web_search) + the
        finalize tool. Order is stable so the tools array caches; cache_control
        is placed on the final (finalize) definition."""
        defs = [dict(d) for d in _GATHERER_DEFS]
        defs += [dict(d) for d in (extra or [])]
        defs.append(dict(FINALIZE_TOOL))
        defs[-1] = {**defs[-1], "cache_control": {"type": "ephemeral"}}
        return defs

    def is_client_tool(self, name: str) -> bool:
        return name in TOOL_ACTIONS or name == FINALIZE_TOOL_NAME

    # -- dispatch --------------------------------------------------------
    def dispatch(self, name: str, tool_input: dict[str, Any]) -> tuple[str, bool]:
        """Execute a tool. Returns (content, is_error)."""
        try:
            if name == "dns_lookup":
                return self._ok(name, tool_input, infra.dns_lookup(tool_input["domain"]))
            if name == "ct_subdomains":
                return self._ok(name, tool_input, infra.ct_subdomains(tool_input["domain"]))
            if name == "rdap_lookup":
                return self._ok(name, tool_input, infra.rdap_lookup(tool_input["domain"]))
            if name == "http_fingerprint":
                return self._active(
                    name, tool_input, tool_input["url"], is_url=True,
                    run=lambda: infra.http_fingerprint(tool_input["url"]),
                )
            if name == "tls_inspect":
                host = tool_input["host"]
                return self._active(
                    name, tool_input, host, is_url=("://" in host),
                    run=lambda: infra.tls_inspect(host, int(tool_input.get("port", 443))),
                )
            if name == "ai_probe":
                return self._ai_probe(tool_input)
            return (f"unknown tool '{name}'", True)
        except KeyError as exc:
            return (f"missing required argument: {exc}", True)
        except Exception as exc:  # never let a tool crash the loop
            self._log(name, tool_input, f"ERROR {type(exc).__name__}")
            return (f"tool error: {type(exc).__name__}: {exc}", True)

    # -- helpers ---------------------------------------------------------
    def _ok(self, name: str, args: dict[str, Any], result: Any) -> tuple[str, bool]:
        self._log(name, args, "ok")
        return (json.dumps(result, default=str), False)

    def _active(
        self, name: str, args: dict[str, Any], target: str, *, is_url: bool, run
    ) -> tuple[str, bool]:
        decision = self.enforcer.check_active(target, is_url=is_url)
        if not decision.allowed:
            self._log(name, args, "REFUSED")
            return (decision.reason, True)
        return self._ok(name, args, run())

    def _ai_probe(self, args: dict[str, Any]) -> tuple[str, bool]:
        endpoint_url = args.get("endpoint_url", "")
        endpoints = self.target.ai_endpoints
        endpoint = None
        if endpoint_url:
            endpoint = next((e for e in endpoints if e.url == endpoint_url), None)
        if endpoint is None and len(endpoints) == 1:
            endpoint = endpoints[0]
        if endpoint is None:
            available = [e.url for e in endpoints]
            return (
                f"no matching AI endpoint. configured endpoints: {available or '[]'}",
                True,
            )
        return self._active(
            "ai_probe", args, endpoint.url, is_url=True,
            run=lambda: ai_target.ai_probe(endpoint, args["prompt"]),
        )

    def _log(self, name: str, args: dict[str, Any], status: str) -> None:
        compact = ", ".join(
            f"{k}={str(v)[:60]}" for k, v in args.items() if k != "prompt"
        )
        if "prompt" in args:
            compact = (compact + ", " if compact else "") + f"prompt={args['prompt'][:60]!r}"
        self.evidence_log.append(f"{name}({compact}) -> {status}")


__all__ = ["ToolRegistry", "TOOL_ACTIONS", "FINALIZE_TOOL_NAME"]

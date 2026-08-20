"""Deterministic collector tests — no network, via a fake dispatch registry."""

import json

from kirmizi_recon import collector
from kirmizi_recon.schemas import AITargetEndpoint, ReconScope, ReconTarget


class FakeRegistry:
    """Records dispatch calls and returns canned JSON, like ToolRegistry."""

    def __init__(self):
        self.calls = []
        self.evidence_log = []

    def dispatch(self, name, tool_input):
        self.calls.append((name, dict(tool_input)))
        self.evidence_log.append(f"{name} ok")
        return (json.dumps({"tool": name, "args": tool_input}), False)

    def names(self):
        return [n for n, _ in self.calls]


def test_passive_collect_runs_only_passive_tools():
    reg = FakeRegistry()
    target = ReconTarget(domains=["acme.example.com"])
    ev = collector.collect(target, ReconScope(mode="passive"), reg)

    assert set(reg.names()) == {"dns_lookup", "ct_subdomains", "rdap_lookup"}
    assert "acme.example.com" in ev.dns
    assert "acme.example.com" in ev.subdomains
    assert "acme.example.com" in ev.rdap
    assert ev.port_scan == {} and ev.endpoints == {}  # no active scans
    assert ev.collection_log == reg.evidence_log


def test_active_collect_runs_active_tools_per_host():
    reg = FakeRegistry()
    target = ReconTarget(
        domains=["acme.example.com"],
        ai_endpoints=[AITargetEndpoint(url="https://api.acme.example.com/chat")],
    )
    scope = ReconScope(
        mode="active",
        in_scope=["acme.example.com", "api.acme.example.com"],
        authorization="PENTEST-1",
        rate_limit_per_sec=1000.0,
    )
    ev = collector.collect(target, scope, reg)

    names = reg.names()
    for active in ("port_scan", "tls_inspect", "http_fingerprint", "endpoint_scan"):
        assert active in names
    # Both the domain and the AI endpoint's host are scanned.
    hosts = set(ev.port_scan.keys())
    assert hosts == {"acme.example.com", "api.acme.example.com"}
    # endpoint_scan is given a URL, not a bare host.
    assert ev.endpoints["acme.example.com"]["args"]["base_url"].startswith("https://")

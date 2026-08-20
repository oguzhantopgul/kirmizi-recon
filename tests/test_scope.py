import pytest

from kirmizi_recon.schemas import ReconScope
from kirmizi_recon.scope import (
    ScopeEnforcer,
    host_matches,
    ip_in_scope,
    is_ip_literal,
    is_local_host,
)


def _active_scope(**over):
    base = dict(
        mode="active",
        in_scope=["acme.example.com", "*.acme.example.com"],
        ai_endpoints=["https://acme.example.com/chat"],
        authorization="PENTEST-1234",
        max_active_requests=100,
        rate_limit_per_sec=1000.0,
    )
    base.update(over)
    return ReconScope(**base)


def test_host_matches_wildcard_and_exact():
    assert host_matches("acme.example.com", "acme.example.com")
    assert host_matches("api.acme.example.com", "*.acme.example.com")
    assert host_matches("acme.example.com", "*.acme.example.com")  # apex matches
    assert not host_matches("evil.com", "*.acme.example.com")
    assert not host_matches("notacme.example.com", "acme.example.com")


def test_is_local_host_literals():
    assert is_local_host("127.0.0.1")
    assert is_local_host("localhost")
    assert is_local_host("10.0.0.5")
    assert is_local_host("192.168.1.1")
    assert not is_local_host("8.8.8.8")
    # link-local (incl. cloud metadata) is NOT auto-authorized by trust_local
    assert not is_local_host("169.254.169.254")


def test_trust_local_excludes_link_local_metadata():
    enf = ScopeEnforcer(
        ReconScope(mode="active", trust_local=True, rate_limit_per_sec=1000.0)
    )
    # metadata endpoint must be refused unless explicitly scoped
    assert not enf.check_active("169.254.169.254").allowed
    assert not enf.check_scan("169.254.169.254").allowed


def test_passive_always_allowed():
    enf = ScopeEnforcer(ReconScope(mode="passive"))
    assert enf.check_passive().allowed


def test_passive_mode_refuses_active():
    enf = ScopeEnforcer(ReconScope(mode="passive"))
    d = enf.check_active("acme.example.com")
    assert not d.allowed
    assert "passive mode" in d.reason


def test_active_in_scope_and_out_of_scope():
    enf = ScopeEnforcer(_active_scope())
    assert enf.check_active("acme.example.com").allowed
    assert enf.check_active("api.acme.example.com").allowed
    out = enf.check_active("evil.example.com")
    assert not out.allowed
    assert "not in the authorized scope" in out.reason


def test_active_ai_endpoint_url():
    enf = ScopeEnforcer(_active_scope())
    assert enf.check_active("https://acme.example.com/chat", is_url=True).allowed
    assert not enf.check_active("https://evil.example.com/chat", is_url=True).allowed


def test_active_request_budget():
    enf = ScopeEnforcer(_active_scope(max_active_requests=1))
    assert enf.check_active("acme.example.com").allowed
    second = enf.check_active("acme.example.com")
    assert not second.allowed
    assert "budget exhausted" in second.reason


def test_trust_local_allows_local_without_authorization():
    scope = ReconScope(mode="active", trust_local=True, rate_limit_per_sec=1000.0)
    enf = ScopeEnforcer(scope)
    assert enf.check_active("127.0.0.1").allowed
    # A non-local, non-scoped target is still refused.
    assert not enf.check_active("acme.example.com").allowed


def test_active_without_authorization_is_rejected_at_construction():
    with pytest.raises(ValueError):
        ReconScope(mode="active", in_scope=["acme.example.com"], authorization="")


# --- IP / CIDR support (port scanning) ------------------------------------


def test_is_ip_literal_and_ip_in_scope():
    assert is_ip_literal("203.0.113.5")
    assert not is_ip_literal("acme.example.com")
    assert ip_in_scope("203.0.113.5", ["203.0.113.0/24"])
    assert ip_in_scope("203.0.113.5", ["203.0.113.5"])
    assert not ip_in_scope("198.51.100.9", ["203.0.113.0/24"])
    # Hostname patterns are ignored by ip_in_scope.
    assert not ip_in_scope("203.0.113.5", ["*.acme.example.com"])


def test_check_scan_cidr_authorization():
    scope = ReconScope(
        mode="active",
        in_scope=["203.0.113.0/24"],
        authorization="PENTEST-1",
        rate_limit_per_sec=1000.0,
    )
    enf = ScopeEnforcer(scope)
    ok = enf.check_scan("203.0.113.5")  # IP literal -> no DNS
    assert ok.allowed and ok.resolved_ip == "203.0.113.5"
    assert not enf.check_scan("198.51.100.9").allowed


def test_check_scan_passive_refused():
    enf = ScopeEnforcer(ReconScope(mode="passive"))
    d = enf.check_scan("203.0.113.5")
    assert not d.allowed and "passive mode" in d.reason


def test_check_scan_trust_local():
    enf = ScopeEnforcer(
        ReconScope(mode="active", trust_local=True, rate_limit_per_sec=1000.0)
    )
    d = enf.check_scan("127.0.0.1")
    assert d.allowed and d.resolved_ip == "127.0.0.1"


def test_check_http_target_blocks_scoped_host_resolving_to_internal():
    # 'localhost' is in scope by name, but resolves to loopback (non-public).
    # Without explicit internal authorization this must be refused (SSRF guard).
    scope = ReconScope(
        mode="active", in_scope=["localhost"], authorization="P-1", rate_limit_per_sec=1000.0
    )
    d = ScopeEnforcer(scope).check_http_target("http://localhost/")
    assert not d.allowed
    assert "non-public IP" in d.reason


def test_check_http_target_allows_internal_when_authorized():
    # trust_local authorizes it...
    d1 = ScopeEnforcer(
        ReconScope(mode="active", in_scope=["localhost"], trust_local=True, rate_limit_per_sec=1000.0)
    ).check_http_target("http://localhost/")
    assert d1.allowed and d1.resolved_ip == "127.0.0.1"

    # ...or an explicit CIDR covering the resolved IP does.
    d2 = ScopeEnforcer(
        ReconScope(
            mode="active",
            in_scope=["localhost", "127.0.0.0/8"],
            authorization="P-1",
            rate_limit_per_sec=1000.0,
        )
    ).check_http_target("http://localhost/")
    assert d2.allowed


def test_check_http_target_allows_public_ip_and_refuses_passive():
    scope = ReconScope(
        mode="active", in_scope=["8.8.8.8"], authorization="P-1", rate_limit_per_sec=1000.0
    )
    assert ScopeEnforcer(scope).check_http_target("http://8.8.8.8/").allowed
    assert not ScopeEnforcer(ReconScope(mode="passive")).check_http_target("http://8.8.8.8/").allowed


def test_check_scan_budget_shared_with_active():
    scope = ReconScope(
        mode="active",
        in_scope=["203.0.113.0/24"],
        authorization="PENTEST-1",
        max_active_requests=1,
        rate_limit_per_sec=1000.0,
    )
    enf = ScopeEnforcer(scope)
    assert enf.check_scan("203.0.113.5").allowed
    assert not enf.check_scan("203.0.113.6").allowed  # budget exhausted

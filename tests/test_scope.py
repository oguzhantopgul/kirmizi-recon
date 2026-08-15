import pytest

from kirmizi_recon.schemas import ReconScope
from kirmizi_recon.scope import (
    ScopeEnforcer,
    host_matches,
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

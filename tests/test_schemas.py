import pytest

from kirmizi_recon.schemas import (
    Finding,
    ReconFindingsPayload,
    ReconReport,
    ReconScope,
    ReconTarget,
    strict_tool_schema,
)


def _collect(node, key, acc):
    if isinstance(node, dict):
        if key in node:
            acc.append(node[key])
        for v in node.values():
            _collect(v, key, acc)
    elif isinstance(node, list):
        for v in node:
            _collect(v, key, acc)


def test_strict_schema_is_hardened():
    schema = strict_tool_schema(ReconFindingsPayload)
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"].keys())

    # No unsupported constraint keywords survive anywhere in the tree.
    for banned in ("minLength", "maxLength", "minimum", "maximum", "default", "title"):
        found: list = []
        _collect(schema, banned, found)
        assert not found, f"{banned} should be stripped"

    # Every nested object also has additionalProperties:false + full required.
    ap: list = []
    _collect(schema, "additionalProperties", ap)
    assert ap and all(v is False for v in ap)


def test_report_from_payload_roundtrip():
    target = ReconTarget(name="t", domains=["acme.example.com"])
    scope = ReconScope(mode="passive")
    payload = ReconFindingsPayload(
        objective_summary="summary",
        findings=[Finding(title="open dir", severity="medium", confidence="high")],
        overall_confidence="medium",
    )
    report = ReconReport.from_payload(
        payload, target=target, scope=scope, evidence_log=["dns_lookup(acme) -> ok"]
    )
    assert report.target_name == "t"
    assert report.scope_mode == "passive"
    assert report.objective_summary == "summary"
    assert report.findings[0].title == "open dir"

    # JSON round-trip preserves the model.
    again = ReconReport.model_validate_json(report.model_dump_json())
    assert again == report


def test_target_requires_domain_or_endpoint():
    with pytest.raises(ValueError):
        ReconTarget(name="empty")

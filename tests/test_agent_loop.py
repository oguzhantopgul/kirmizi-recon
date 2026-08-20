"""Offline test of the manual agentic loop with a fake Claude client.

Exercises: tool dispatch, scope-refusal surfaced as an error tool_result (no
network — an active tool refused in passive mode), and finalize_report parsing
into a ReconReport.
"""

from types import SimpleNamespace

from kirmizi_recon.agent import ReconAgent
from kirmizi_recon.config import Settings
from kirmizi_recon.schemas import Evidence, ReconScope, ReconTarget


def _tool_use(tool_id, name, tool_input):
    return SimpleNamespace(type="tool_use", id=tool_id, name=name, input=tool_input)


def _resp(stop_reason, content):
    return SimpleNamespace(stop_reason=stop_reason, content=content, stop_details=None)


class _Messages:
    def __init__(self, queue, sink):
        self._queue = queue
        self._sink = sink

    def create(self, **kwargs):
        # Snapshot list membership at call time (agent mutates the list in place).
        self._sink.append(list(kwargs["messages"]))
        return self._queue.pop(0)


class FakeClient:
    def __init__(self, responses):
        self.received = []
        self.messages = _Messages(responses, self.received)
        self.beta = SimpleNamespace(messages=self.messages)


def test_loop_refusal_then_finalize():
    responses = [
        # Turn 1: model asks for an ACTIVE tool while scope is passive -> refused.
        _resp("tool_use", [_tool_use("t1", "http_fingerprint", {"url": "https://example.com"})]),
        # Turn 2: model finalizes.
        _resp(
            "tool_use",
            [
                _tool_use(
                    "t2",
                    "finalize_report",
                    {
                        "objective_summary": "did recon",
                        "attack_surface_summary": "small",
                        "overall_confidence": "medium",
                        "findings": [
                            {"title": "missing HSTS", "severity": "low", "confidence": "high"}
                        ],
                        "recommended_next_steps": ["probe auth"],
                    },
                )
            ],
        ),
    ]
    agent = ReconAgent(
        settings=Settings(use_fallbacks=False, enable_web=False),
        client=FakeClient(responses),
    )
    target = ReconTarget(name="acme", domains=["example.com"])
    scope = ReconScope(mode="passive")

    # Call analyze() directly with a prebuilt (empty) Evidence — avoids the
    # deterministic collection phase hitting the network in a unit test.
    report = agent.analyze(target, scope, Evidence())

    assert report.target_name == "acme"
    assert report.objective_summary == "did recon"
    assert report.findings[0].title == "missing HSTS"
    assert report.recommended_next_steps == ["probe auth"]
    # The active tool was refused (no network) and logged.
    assert any("http_fingerprint" in e and "REFUSED" in e for e in report.evidence_log)
    # Refusal is a tool_result, not a run error.
    assert report.errors == []

    # The second request carried a tool_result with is_error=True for t1.
    second_request_msgs = agent.client.received[1]
    tool_results = second_request_msgs[-1]["content"]
    assert tool_results[0]["tool_use_id"] == "t1"
    assert tool_results[0]["is_error"] is True


def test_loop_nudges_then_reports_when_model_ends_without_finalize():
    responses = [
        _resp("end_turn", [SimpleNamespace(type="text", text="I'm done thinking.")]),
        _resp(
            "tool_use",
            [_tool_use("t9", "finalize_report", {"objective_summary": "ok"})],
        ),
    ]
    agent = ReconAgent(
        settings=Settings(use_fallbacks=False, enable_web=False),
        client=FakeClient(responses),
    )
    report = agent.analyze(ReconTarget(domains=["example.com"]), ReconScope(), Evidence())
    assert report.objective_summary == "ok"


def test_run_calls_collect_then_analyze(monkeypatch):
    # run() should run the deterministic collect phase, then the agentic analyze
    # phase. Stub collect to avoid the network; assert the seam is wired.
    from kirmizi_recon import agent as agent_mod

    called = {"collect": 0}

    def fake_collect(target, scope, registry):
        called["collect"] += 1
        return Evidence(collection_log=["dns_lookup(example.com) -> ok"])

    monkeypatch.setattr(agent_mod.collector, "collect", fake_collect)

    responses = [
        _resp("tool_use", [_tool_use("t1", "finalize_report", {"objective_summary": "done"})]),
    ]
    agent = ReconAgent(
        settings=Settings(use_fallbacks=False, enable_web=False),
        client=FakeClient(responses),
    )
    report = agent.run(ReconTarget(name="acme", domains=["example.com"]), ReconScope())
    assert called["collect"] == 1
    assert report.objective_summary == "done"

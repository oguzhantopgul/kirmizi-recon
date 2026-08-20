from kirmizi_recon.tools.infra import (
    _group_endpoint_results,
    endpoint_scan,
    normalize_base_url,
)
from kirmizi_recon.wordlists import API_ENDPOINTS, _dedupe, load_wordlist


def test_wordlist_is_clean_and_covers_key_paths():
    assert len(API_ENDPOINTS) > 300
    assert all(p.startswith("/") for p in API_ENDPOINTS)
    assert len(API_ENDPOINTS) == len(set(API_ENDPOINTS))  # no duplicates
    # base (AI/LLM) coverage retained
    for p in ("/v1/chat/completions", "/api/generate", "/v1/models"):
        assert p in API_ENDPOINTS
    # augmented high-value coverage
    for p in (
        "/actuator/env",
        "/v3/api-docs",
        "/graphiql",
        "/.well-known/openid-configuration",
        "/.well-known/ai-plugin.json",
        "/v1/messages",
        "/wp-json",
        "/.git/config",
    ):
        assert p in API_ENDPOINTS


def test_dedupe_normalizes_and_orders():
    assert _dedupe(["a", "/a", "/b", "b", ""]) == ["/a", "/b"]


def test_normalize_base_url():
    assert normalize_base_url("acme.example.com") == "https://acme.example.com/"
    assert normalize_base_url("https://x/y/") == "https://x/y/"
    assert normalize_base_url("http://x") == "http://x/"


def test_group_endpoint_results_classifies_and_hides_404():
    results = [
        {"path": "/api", "status": 200, "length": 10},
        {"path": "/admin", "status": 302, "length": 0, "location": "/login"},
        {"path": "/api/users", "status": 401, "length": 5},
        {"path": "/secret", "status": 403, "length": 5},
        {"path": "/v1/chat/completions", "status": 405, "length": 5},
        {"path": "/nope", "status": 404, "length": 0},
        {"path": "/boom", "status": "ERROR", "length": 0, "error": "timeout"},
    ]
    grouped = _group_endpoint_results("https://x/", 7, results)
    c = grouped["counts"]
    assert (c["2xx"], c["3xx"], c["401"], c["403"], c["405"], c["404"], c["error"]) == (
        1, 1, 1, 1, 1, 1, 1
    )
    paths = [r["path"] for r in grouped["interesting"]]
    assert "/nope" not in paths and "/boom" not in paths  # 404 + error excluded
    assert set(paths) == {"/api", "/admin", "/api/users", "/secret", "/v1/chat/completions"}


def test_endpoint_scan_skips_offhost_paths():
    # A model-supplied absolute URL must NOT escape the authorized origin.
    # 127.0.0.1:9 has nothing listening -> the on-origin path errors fast; the
    # off-host path is skipped before any request is made.
    result = endpoint_scan(
        "http://127.0.0.1:9",
        ["/", "http://evil.example.com/exfil", "//evil.example.com/x"],
        timeout=2.0,
        throttle=None,
    )
    assert result["counts"]["offhost_skipped"] == 1  # only the absolute URL
    paths = [r["path"] for r in result["interesting"]]
    assert "http://evil.example.com/exfil" not in paths


def test_load_wordlist(tmp_path):
    f = tmp_path / "wl.txt"
    f.write_text("# comment\n/a\nb\n\n  /c  \n/a\n")
    assert load_wordlist(str(f)) == ["/a", "/b", "/c"]

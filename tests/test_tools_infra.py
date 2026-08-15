from kirmizi_recon.schemas import AITargetEndpoint
from kirmizi_recon.tools.ai_target import build_body, dig_path
from kirmizi_recon.tools.infra import _cookie_names, _flatten_name


def test_dig_path_nested():
    obj = {"choices": [{"message": {"content": "hi"}}]}
    assert dig_path(obj, "choices.0.message.content") == "hi"
    assert dig_path(obj, "choices.5.message.content") is None
    assert dig_path(obj, "nope") is None


def test_build_body_escapes_prompt():
    tmpl = '{"messages": [{"role": "user", "content": {prompt}}]}'
    body = build_body(tmpl, 'say "hi"\nthen stop')
    assert body["messages"][0]["content"] == 'say "hi"\nthen stop'


def test_default_endpoint_template_parses():
    ep = AITargetEndpoint(url="https://x/y")
    body = build_body(ep.request_template, "hello")
    assert body["messages"][0]["content"] == "hello"


def test_cookie_names():
    raw = ["sid=abc; Path=/; HttpOnly", "theme=dark; Path=/"]
    assert _cookie_names(raw) == ["sid", "theme"]


def test_flatten_name():
    rdns = ((("commonName", "acme.example.com"),), (("organizationName", "Acme"),))
    assert _flatten_name(rdns) == "commonName=acme.example.com, organizationName=Acme"
    assert _flatten_name(None) == ""

"""AI-target recon: probe the configured target AI endpoint.

``ai_probe`` is a generic HTTP POST so the agent can talk to any provider. The
probe prompt is substituted (JSON-encoded) into the endpoint's
``request_template``, and the reply text is extracted via ``response_path``.
It returns the raw target response; Claude infers the model family, guardrails,
prompt-leak indicators, and injection surface from a battery of these probes.

This is an ACTIVE action — the registry enforces scope before it runs.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ..schemas import AITargetEndpoint

_TIMEOUT = 30.0
_UA = "kirmizi-recon/0.1 (authorized security testing)"
_MAX_RAW = 4000


def dig_path(obj: Any, path: str) -> Any:
    """Traverse a JSON object by a dotted path; integer segments index lists."""
    cur = obj
    for seg in path.split("."):
        if seg == "":
            continue
        if isinstance(cur, list):
            try:
                cur = cur[int(seg)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(seg)
        else:
            return None
        if cur is None:
            return None
    return cur


def build_body(template: str, prompt: str) -> Any:
    """Substitute the JSON-encoded prompt into the template and parse to a body."""
    injected = template.replace("{prompt}", json.dumps(prompt))
    return json.loads(injected)


def ai_probe(endpoint: AITargetEndpoint, prompt: str) -> dict[str, Any]:
    """Send a single probe prompt to the target AI endpoint and return the raw
    response plus the extracted reply text."""
    result: dict[str, Any] = {"endpoint": endpoint.url, "prompt": prompt}
    try:
        body = build_body(endpoint.request_template, prompt)
    except json.JSONDecodeError as exc:
        result["error"] = f"request_template did not parse as JSON: {exc}"
        return result

    headers = {"User-Agent": _UA, "Content-Type": "application/json", **endpoint.headers}
    try:
        # Do NOT follow redirects: endpoint headers may carry an Authorization
        # token, and a 3xx would resend it to the redirect target's host.
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=False) as client:
            resp = client.request(endpoint.method, endpoint.url, json=body, headers=headers)
        result["status"] = resp.status_code
        if 300 <= resp.status_code < 400:
            result["redirect_location"] = resp.headers.get("location", "")
        raw_text = resp.text
        result["raw_response"] = raw_text[:_MAX_RAW]
        result["truncated"] = len(raw_text) > _MAX_RAW
        try:
            parsed = resp.json()
            reply = dig_path(parsed, endpoint.response_path)
            result["reply"] = reply if reply is not None else "(response_path not found)"
        except json.JSONDecodeError:
            result["reply"] = "(non-JSON response; see raw_response)"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result

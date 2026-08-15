"""Infrastructure / OSINT recon gatherers.

Each function returns a JSON-serializable dict of *raw evidence* — Claude does
the interpretation. Passive functions read public/third-party sources or DNS and
never touch the target directly; active functions (``http_fingerprint``,
``tls_inspect``) send traffic to the target and are gated by scope enforcement
in the registry.
"""

from __future__ import annotations

import re
import socket
import ssl
from typing import Any

import httpx

try:  # dnspython is a hard dependency, but degrade gracefully if unavailable.
    import dns.resolver

    _HAVE_DNS = True
except Exception:  # pragma: no cover
    _HAVE_DNS = False

_TIMEOUT = 15.0
_UA = "kirmizi-recon/0.1 (authorized security testing)"


def dns_lookup(domain: str) -> dict[str, Any]:
    """Resolve common DNS record types for a domain (passive)."""
    if not _HAVE_DNS:
        return {"domain": domain, "error": "dnspython not installed"}
    records: dict[str, Any] = {"domain": domain}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = _TIMEOUT
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME"):
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = sorted(a.to_text().strip('"') for a in answers)
        except Exception as exc:  # NXDOMAIN, NoAnswer, timeout, etc.
            records[rtype] = f"(none: {type(exc).__name__})"
    return records


def ct_subdomains(domain: str, limit: int = 200) -> dict[str, Any]:
    """Discover subdomains from certificate-transparency logs via crt.sh
    (passive — queries a third party, not the target)."""
    url = "https://crt.sh/"
    try:
        with httpx.Client(timeout=_TIMEOUT, headers={"User-Agent": _UA}) as client:
            resp = client.get(url, params={"q": f"%.{domain}", "output": "json"})
        resp.raise_for_status()
        rows = resp.json()
    except Exception as exc:
        return {"domain": domain, "error": f"{type(exc).__name__}: {exc}"}

    names: set[str] = set()
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain):
                names.add(name)
    ordered = sorted(names)
    return {
        "domain": domain,
        "count": len(ordered),
        "subdomains": ordered[:limit],
        "truncated": len(ordered) > limit,
    }


def rdap_lookup(domain: str) -> dict[str, Any]:
    """RDAP (modern WHOIS) lookup via rdap.org (passive)."""
    try:
        with httpx.Client(
            timeout=_TIMEOUT, headers={"User-Agent": _UA}, follow_redirects=True
        ) as client:
            resp = client.get(f"https://rdap.org/domain/{domain}")
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {"domain": domain, "error": f"{type(exc).__name__}: {exc}"}

    registrar = ""
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            for item in entity.get("vcardArray", [[], []])[1]:
                if item and item[0] == "fn":
                    registrar = item[3]
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    return {
        "domain": domain,
        "handle": data.get("handle", ""),
        "registrar": registrar,
        "status": data.get("status", []),
        "events": events,
        "nameservers": [ns.get("ldhName", "") for ns in data.get("nameservers", [])],
    }


_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]
_FINGERPRINT_HEADERS = ["server", "x-powered-by", "via", "x-aspnet-version"]


def http_fingerprint(url: str) -> dict[str, Any]:
    """Fetch the target over HTTP(S): status, banners, security headers, title,
    and robots.txt (ACTIVE — sends requests to the target)."""
    if "://" not in url:
        url = "https://" + url
    result: dict[str, Any] = {"url": url}
    try:
        with httpx.Client(
            timeout=_TIMEOUT,
            headers={"User-Agent": _UA},
            follow_redirects=True,
            verify=True,
        ) as client:
            resp = client.get(url)
            result["status"] = resp.status_code
            result["final_url"] = str(resp.url)
            result["fingerprint_headers"] = {
                h: resp.headers[h] for h in _FINGERPRINT_HEADERS if h in resp.headers
            }
            result["security_headers_present"] = {
                h: (h in resp.headers) for h in _SECURITY_HEADERS
            }
            result["set_cookie_names"] = _cookie_names(resp.headers.get_list("set-cookie"))
            title = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:20000], re.I | re.S)
            result["title"] = title.group(1).strip() if title else ""

            robots = client.get(str(resp.url).rstrip("/") + "/robots.txt")
            result["robots_txt"] = (
                robots.text[:2000] if robots.status_code == 200 else f"(status {robots.status_code})"
            )
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def _cookie_names(set_cookies: list[str]) -> list[str]:
    names = []
    for raw in set_cookies:
        names.append(raw.split("=", 1)[0].strip())
    return names


def tls_inspect(host: str, port: int = 443) -> dict[str, Any]:
    """Inspect the TLS certificate presented by the target (ACTIVE — performs a
    TLS handshake). Falls back to reporting the negotiated protocol/cipher when
    certificate validation fails (e.g. self-signed)."""
    if "://" in host:
        from urllib.parse import urlparse

        host = urlparse(host).hostname or host

    result: dict[str, Any] = {"host": host, "port": port}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                result["protocol"] = tls.version()
                cipher = tls.cipher()
                result["cipher"] = cipher[0] if cipher else ""
                result["valid"] = True
                result["subject"] = _flatten_name(cert.get("subject"))
                result["issuer"] = _flatten_name(cert.get("issuer"))
                result["not_before"] = cert.get("notBefore", "")
                result["not_after"] = cert.get("notAfter", "")
                result["subject_alt_names"] = [
                    v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"
                ]
    except ssl.SSLCertVerificationError as exc:
        result["valid"] = False
        result["verify_error"] = str(exc)
        result.update(_tls_unverified(host, port))
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def _tls_unverified(host: str, port: int) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    out: dict[str, Any] = {}
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                out["protocol"] = tls.version()
                cipher = tls.cipher()
                out["cipher"] = cipher[0] if cipher else ""
    except Exception as exc:  # pragma: no cover
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def _flatten_name(rdns: Any) -> str:
    if not rdns:
        return ""
    parts = []
    for rdn in rdns:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)

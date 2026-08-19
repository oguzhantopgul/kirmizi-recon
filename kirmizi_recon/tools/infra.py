"""Infrastructure / OSINT recon gatherers.

Each function returns a JSON-serializable dict of *raw evidence* — Claude does
the interpretation. Passive functions read public/third-party sources or DNS and
never touch the target directly; active functions (``http_fingerprint``,
``tls_inspect``) send traffic to the target and are gated by scope enforcement
in the registry.
"""

from __future__ import annotations

import concurrent.futures
import re
import shutil
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
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


# ---------------------------------------------------------------------------
# Port scan / service enumeration
# ---------------------------------------------------------------------------

# Curated common TCP ports — used for the top-100 default and by the fallback
# (which has no port database of its own).
TOP_100_PORTS = [
    7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
    135, 139, 143, 144, 161, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1434, 1521, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 5985, 6000,
    6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000,
    9090, 9100, 9200, 10000, 27017, 32768,
]
WEB_PORTS = [80, 443, 3000, 4443, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090]

_PORT_SPEC_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
_MAX_FALLBACK_PORTS = 2048
_NMAP_TIMEOUT = 220
_SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 587: "smtp",
    993: "imaps", 995: "pop3s", 1433: "ms-sql", 1521: "oracle", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}
_HTTP_PORTS = {80, 81, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090}


def _normalize_ports(spec: str) -> tuple[str, Any]:
    """Return (kind, value): ('top', N) | ('list', [ints]) | ('spec', 'nmap-str').
    Raises ValueError on anything that isn't a known keyword or a numeric spec
    (guards against argument injection into nmap)."""
    spec = (spec or "top-100").strip().lower()
    if spec in ("", "top-100", "top100"):
        return ("top", 100)
    if spec in ("top-1000", "top1000"):
        return ("top", 1000)
    if spec == "web":
        return ("list", list(WEB_PORTS))
    if _PORT_SPEC_RE.match(spec):
        return ("spec", spec)
    raise ValueError(
        f"invalid ports '{spec}'. Use 'top-100', 'top-1000', 'web', or a numeric "
        f"spec like '22,80,443' or '1-1024'."
    )


def _expand_spec(spec: str) -> list[int]:
    ports: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    ports = sorted({p for p in ports if 0 < p <= 65535})
    return ports[:_MAX_FALLBACK_PORTS]


def port_scan(target_ip: str, ports: str = "top-100", service_detection: bool = True) -> dict[str, Any]:
    """Scan an authorized IP for open ports and (best-effort) services.

    Uses nmap ``-sV`` when available for real service/version enumeration; falls
    back to a pure-Python TCP connect scan (open ports + light banners, no
    version detection) otherwise. ``target_ip`` must already be scope-authorized
    and resolved by the caller.
    """
    try:
        kind, value = _normalize_ports(ports)
    except ValueError as exc:
        return {"target": target_ip, "error": str(exc)}

    if shutil.which("nmap"):
        return _run_nmap(target_ip, kind, value, service_detection)
    return _run_fallback(target_ip, kind, value, service_detection)


def _run_nmap(ip: str, kind: str, value: Any, service: bool) -> dict[str, Any]:
    # We build the argv ourselves (shell=False); the model never controls it.
    argv = ["nmap", "-Pn", "-sT", "-T3", "-oX", "-", "--host-timeout", "180s"]
    if service:
        argv.append("-sV")
    if kind == "top":
        argv += ["--top-ports", str(value)]
    elif kind == "list":
        argv += ["-p", ",".join(str(p) for p in value)]
    else:  # spec (validated numeric string)
        argv += ["-p", value]
    argv.append(ip)

    try:
        proc = subprocess.run(argv, capture_output=True, timeout=_NMAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"target": ip, "engine": "nmap", "error": "nmap timed out"}
    except OSError as exc:
        return {"target": ip, "engine": "nmap", "error": f"nmap failed: {exc}"}

    try:
        open_ports = _parse_nmap_xml(proc.stdout)
    except ET.ParseError:
        return {
            "target": ip,
            "engine": "nmap",
            "error": "could not parse nmap output",
            "stderr": proc.stderr.decode("utf-8", "replace")[:500],
        }
    return {
        "target": ip,
        "engine": "nmap",
        "degraded": False,
        "open_ports": open_ports,
        "open_count": len(open_ports),
    }


def _parse_nmap_xml(data: bytes) -> list[dict[str, Any]]:
    if not data.strip():
        return []
    root = ET.fromstring(data)
    out: list[dict[str, Any]] = []
    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            out.append(
                {
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol", "tcp"),
                    "state": "open",
                    "service": svc.get("name", "") if svc is not None else "",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                }
            )
    return sorted(out, key=lambda d: d["port"])


def _run_fallback(ip: str, kind: str, value: Any, service: bool) -> dict[str, Any]:
    if kind == "top":
        port_list = list(TOP_100_PORTS)  # no port DB — curated common set only
        note = (
            "nmap not installed: pure-Python connect scan over curated common "
            "ports; no version detection."
        )
        if value == 1000:
            note += " (top-1000 requested but fallback is limited to ~100 ports.)"
    elif kind == "list":
        port_list = list(value)
        note = "nmap not installed: pure-Python connect scan; no version detection."
    else:
        port_list = _expand_spec(value)
        note = "nmap not installed: pure-Python connect scan; no version detection."

    open_ports = _connect_scan(ip, port_list, service)
    return {
        "target": ip,
        "engine": "python-fallback",
        "degraded": True,
        "service_detection": "limited (banner only)" if service else "none",
        "note": note,
        "open_ports": open_ports,
        "open_count": len(open_ports),
    }


def _connect_scan(
    ip: str, ports: list[int], service: bool, timeout: float = 1.0, workers: int = 100
) -> list[dict[str, Any]]:
    def probe(port: int) -> dict[str, Any] | None:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                banner = _grab_banner(sock, port, timeout) if service else ""
        except OSError:
            return None
        return {
            "port": port,
            "protocol": "tcp",
            "state": "open",
            "service": _SERVICE_HINTS.get(port, ""),
            "product": "",
            "version": "",
            "banner": banner,
        }

    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(probe, ports):
            if r is not None:
                results.append(r)
    return sorted(results, key=lambda d: d["port"])


def _grab_banner(sock: socket.socket, port: int, timeout: float) -> str:
    try:
        sock.settimeout(timeout)
        if port in _HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(256)
        return data.decode("utf-8", "replace").strip()[:200]
    except OSError:
        return ""

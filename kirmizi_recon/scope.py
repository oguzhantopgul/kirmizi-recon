"""Scope enforcement + rate limiting — the fail-closed safety boundary.

Every active tool consults a :class:`ScopeEnforcer` *before* touching the
target. The two gates (from the plan) are enforced here:

1. ``mode == "active"`` — intent (the ``--active`` flag)
2. the specific target is ``in_scope`` — permission

Missing either keeps the action refused. Refusals are returned as a
:class:`Decision` (not raised) so callers can surface them to Claude as an
error tool_result and let it adapt, rather than crashing the run.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from .schemas import ReconScope


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""


def host_from_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"//{url}", scheme="https")
    return (parsed.hostname or "").lower()


def is_local_host(host: str) -> bool:
    """True for localhost and RFC-1918 / loopback / link-local addresses."""
    if not host:
        return False
    host = host.lower()
    if host in {"localhost", "localhost.localdomain"}:
        return True
    # Resolve a literal address if possible; otherwise try DNS, but never fail
    # open — an unresolvable host is treated as non-local.
    candidates: list[str] = []
    try:
        ipaddress.ip_address(host)
        candidates.append(host)
    except ValueError:
        try:
            candidates.append(socket.gethostbyname(host))
        except OSError:
            return False
    for cand in candidates:
        try:
            ip = ipaddress.ip_address(cand)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return True
    return False


def host_matches(host: str, pattern: str) -> bool:
    """Match a host against an in-scope pattern. Supports a leading ``*.``
    wildcard (matches the domain itself and any subdomain)."""
    host = host.lower().strip().rstrip(".")
    pattern = pattern.lower().strip().rstrip(".")
    if not host or not pattern:
        return False
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern


class TokenBucket:
    """Simple thread-safe token bucket. ``acquire`` blocks until a token is
    available, bounding the rate of active requests to the target."""

    def __init__(self, rate_per_sec: float, capacity: float | None = None) -> None:
        self.rate = max(rate_per_sec, 0.001)
        self.capacity = capacity if capacity is not None else max(self.rate, 1.0)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = 1.0 - self._tokens
                wait = deficit / self.rate
            time.sleep(min(wait, 1.0))


class ScopeEnforcer:
    """Enforces a :class:`ReconScope`. Thread-safe request counting + rate
    limiting for active actions."""

    def __init__(self, scope: ReconScope) -> None:
        self.scope = scope
        self._bucket = TokenBucket(scope.rate_limit_per_sec)
        self._active_count = 0
        self._lock = threading.Lock()

    @property
    def active_count(self) -> int:
        return self._active_count

    # -- passive is always permitted -------------------------------------
    def check_passive(self) -> Decision:
        return Decision(True)

    # -- active is double-gated + budgeted + rate-limited ----------------
    def check_active(self, target: str, *, is_url: bool = False) -> Decision:
        if self.scope.mode != "active":
            return Decision(
                False,
                "refused: passive mode. Active actions require --active plus an "
                "in-scope, authorized target.",
            )

        host = host_from_url(target) if is_url else target.lower().strip().rstrip(".")
        local_ok = self.scope.trust_local and is_local_host(host)

        in_scope = local_ok
        if not in_scope and is_url:
            in_scope = target in self.scope.ai_endpoints or any(
                host_matches(host, p) for p in self.scope.in_scope
            )
        elif not in_scope:
            in_scope = any(host_matches(host, p) for p in self.scope.in_scope)

        if not in_scope:
            return Decision(
                False,
                f"refused: '{target}' is not in the authorized scope "
                f"(in_scope={self.scope.in_scope or '[]'}"
                + (
                    f", ai_endpoints={self.scope.ai_endpoints or '[]'}"
                    if is_url
                    else ""
                )
                + ").",
            )

        with self._lock:
            if self._active_count >= self.scope.max_active_requests:
                return Decision(
                    False,
                    f"refused: active-request budget exhausted "
                    f"({self.scope.max_active_requests}).",
                )
            self._active_count += 1

        self._bucket.acquire()
        return Decision(True)

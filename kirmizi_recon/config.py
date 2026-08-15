"""Runtime settings for the recon agent (env-overridable)."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    model: str = "claude-opus-5"
    effort: str = "high"  # low | medium | high | xhigh | max
    max_tokens: int = 16000
    max_turns: int = 40
    enable_web: bool = True  # allow Claude's server-side web_search/web_fetch for OSINT
    use_fallbacks: bool = True  # server-side refusal fallbacks (benign-request rescue)
    fallback_beta: str = "server-side-fallback-2026-07-01"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            model=os.getenv("KIRMIZI_MODEL", cls.model),
            effort=os.getenv("KIRMIZI_EFFORT", cls.effort),
            max_tokens=int(os.getenv("KIRMIZI_MAX_TOKENS", cls.max_tokens)),
            max_turns=int(os.getenv("KIRMIZI_MAX_TURNS", cls.max_turns)),
            enable_web=_env_bool("KIRMIZI_ENABLE_WEB", cls.enable_web),
            use_fallbacks=_env_bool("KIRMIZI_USE_FALLBACKS", cls.use_fallbacks),
        )

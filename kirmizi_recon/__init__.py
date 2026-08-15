"""kirmizi-recon — AI Red Teaming Recon Agent.

Hybrid reconnaissance (target AI application + surrounding infrastructure/OSINT)
driven by Claude. Passive by default; active probing is gated behind explicit
scope authorization. The core `ReconAgent.run()` is interface-agnostic so a
future A2A server can wrap it without refactoring.
"""

from .schemas import ReconReport, ReconScope, ReconTarget

__version__ = "0.1.0"

__all__ = ["ReconReport", "ReconScope", "ReconTarget", "__version__"]

from __future__ import annotations

from datetime import datetime

from .schema import ThreatContext


def is_active(context: ThreatContext, at_time: datetime) -> bool:
    """Functional form for callers that prefer lifecycle helpers."""
    return context.is_active(at_time)

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

ValueType = Literal["boolean", "integer", "range", "enum", "text", "unknown"]
ConfigurationState = Literal["enabled", "disabled", "not_configured"]
ComparisonOperator = Literal[">=", "<=", "=", "between"]


class ParsedRecommendation(BaseModel):
    raw_text: str
    normalized_text: str
    value_type: ValueType = "unknown"
    bool_value: bool | None = None
    int_value: int | None = None
    min_value: int | None = None
    max_value: int | None = None
    enum_value: str | None = None
    configuration_state: ConfigurationState | None = None
    operator: ComparisonOperator | None = None
    quality_flags: list[str] = Field(default_factory=list)


def parse_recommendation(text: str | None) -> ParsedRecommendation:
    raw = (text or "").strip()
    normalized = re.sub(r"\s+", " ", raw).strip()
    lower = normalized.lower()

    parsed = ParsedRecommendation(raw_text=raw, normalized_text=normalized)

    if not normalized:
        parsed.quality_flags.append("missing_recommendation")
        return parsed

    if lower in {"enabled", "enable"}:
        parsed.value_type = "boolean"
        parsed.bool_value = True
        parsed.configuration_state = "enabled"
        return parsed

    if lower in {"disabled", "disable"}:
        parsed.value_type = "boolean"
        parsed.bool_value = False
        parsed.configuration_state = "disabled"
        return parsed

    if lower == "not configured":
        parsed.value_type = "enum"
        parsed.enum_value = "not_configured"
        parsed.configuration_state = "not_configured"
        return parsed

    range_match = re.search(r"(\d+)\s*(?:-|to)\s*(\d+)", lower)
    if range_match:
        parsed.value_type = "range"
        parsed.operator = "between"
        parsed.min_value = int(range_match.group(1))
        parsed.max_value = int(range_match.group(2))
        if parsed.min_value > parsed.max_value:
            parsed.min_value, parsed.max_value = parsed.max_value, parsed.min_value
            parsed.quality_flags.append("range_reordered")
        return parsed

    int_match = re.search(r"^(<=|>=|=|is\s+)?\s*(\d+)$", lower)
    if int_match:
        parsed.value_type = "integer"
        parsed.int_value = int(int_match.group(2))
        token = (int_match.group(1) or "=").strip()
        parsed.operator = "=" if token == "is" else token  # type: ignore[assignment]
        return parsed

    bounded_match = re.search(r"(\d+)", lower)
    if bounded_match and any(
        op in lower for op in ["at least", "maximum", "min", "max"]
    ):
        parsed.value_type = "integer"
        parsed.int_value = int(bounded_match.group(1))
        parsed.operator = (
            ">=" if any(op in lower for op in ["at least", "minimum", "min"]) else "<="
        )
        parsed.quality_flags.append("bounded_expression")
        return parsed

    enum_match = re.search(
        r"\b(high|medium|low|success and failure|success|failure|allow|block|audit)\b",
        lower,
    )
    if enum_match:
        parsed.value_type = "enum"
        parsed.enum_value = enum_match.group(1)
        return parsed

    parsed.value_type = "text"
    if len(normalized) < 3:
        parsed.quality_flags.append("ambiguous_text")
    return parsed

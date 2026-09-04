from __future__ import annotations

import json
import re
from enum import Enum


class ComparisonResult(str, Enum):
    MATCH = "match"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"


TRUE_VALUES = {"true", "enabled", "enable", "1", "yes"}
FALSE_VALUES = {"false", "disabled", "disable", "0", "no"}


def _decode(value: str) -> object:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _normalized(value: object) -> object:
    if isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else value
    if isinstance(value, str):
        text = re.sub(r"\s+", " ", value.strip()).casefold()
        if text in TRUE_VALUES:
            return True
        if text in FALSE_VALUES:
            return False
        if re.fullmatch(r"-?\d+", text):
            return int(text)
        return text
    return value


def compare_value(desired: object, observed_json: str) -> ComparisonResult:
    observed = _normalized(_decode(observed_json))
    expected = _normalized(desired)
    if isinstance(observed, (dict, list)) or isinstance(expected, (dict, list)):
        return ComparisonResult.UNKNOWN
    return ComparisonResult.MATCH if observed == expected else ComparisonResult.MISMATCH

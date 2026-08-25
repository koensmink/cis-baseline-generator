from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ALLOWED_IMPLEMENTATION_TYPES = {
    "settings_catalog": "settings_catalog",
    "administrative_template": "administrative_template",
    "endpoint_security": "endpoint_security",
    "custom_oma_uri": "custom_oma_uri",
    "policy_csp": "policy_csp",
    "registry": "registry",
    "powershell": "powershell",
    "not_manageable": "not_manageable",
    "unknown": "unknown",
}


IMPLEMENTATION_TYPE_ALIASES = {
    "settings catalog": "settings_catalog",
    "settings_catalog": "settings_catalog",
    "device restrictions": "policy_csp",
    "device restriction": "policy_csp",
    "device configuration": "policy_csp",
    "device configuration profile": "policy_csp",
    "configuration profile": "policy_csp",
    "intune configuration profile": "policy_csp",
    "administrative template": "administrative_template",
    "administrative templates": "administrative_template",
    "endpoint security": "endpoint_security",
    "custom oma-uri": "custom_oma_uri",
    "custom oma uri": "custom_oma_uri",
    "oma-uri": "custom_oma_uri",
    "oma uri": "custom_oma_uri",
    "policy csp": "policy_csp",
    "registry": "registry",
    "powershell": "powershell",
    "powershell script": "powershell",
    "script": "powershell",
    "manual triage": "unknown",
    "manual review": "unknown",
    "not manageable": "not_manageable",
}


ALLOWED_INTUNE_AREAS = {
    "settings_catalog": "Settings Catalog",
    "administrative_template": "Administrative Templates",
    "endpoint_security": "Endpoint Security",
    "custom_oma_uri": "Custom OMA-URI",
    "policy_csp": "Policy CSP",
    "registry": "Registry",
    "powershell": "PowerShell",
    "not_manageable": "Not Manageable",
    "unknown": "Manual Review",
}


AREA_ALIASES = {
    "settings catalog": "Settings Catalog",
    "device restrictions": "Configuration Profile",
    "device restriction": "Configuration Profile",
    "device configuration": "Configuration Profile",
    "device configuration profile": "Configuration Profile",
    "configuration profile": "Configuration Profile",
    "intune configuration profile": "Configuration Profile",
    "administrative template": "Administrative Templates",
    "administrative templates": "Administrative Templates",
    "endpoint security": "Endpoint Security",
    "custom oma-uri": "Custom OMA-URI",
    "custom oma uri": "Custom OMA-URI",
    "compliance policy": "Compliance Policy",
    "compliance": "Compliance Policy",
    "powershell scripts": "Scripts",
    "powershell script": "Scripts",
    "script": "Scripts",
    "manual triage": "Manual Review",
    "manual review": "Manual Review",
}


@dataclass
class NormalizedSuggestion:
    suggested_implementation_type: str
    suggested_intune_area: str
    suggested_setting_name: str
    suggested_value: str
    confidence: float
    reasoning: str
    suggested_catalog_identifier: str | None
    mapping_source: str
    needs_validation: bool
    normalization_notes: list[str]


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Enabled" if value else "Disabled"
    return str(value).strip()


def _normalize_confidence(value: Any) -> float:
    if value is None:
        return 0.5

    if isinstance(value, (int, float)):
        v = float(value)
        return max(0.0, min(1.0, v))

    text = str(value).strip().lower()

    mapping = {
        "very high": 0.95,
        "high": 0.85,
        "medium": 0.60,
        "moderate": 0.60,
        "low": 0.35,
        "very low": 0.15,
    }
    if text in mapping:
        return mapping[text]

    try:
        v = float(text)
        return max(0.0, min(1.0, v))
    except ValueError:
        return 0.5


def _normalize_implementation_type(value: Any) -> tuple[str, str | None]:
    text = _clean_text(value).lower()
    if text in IMPLEMENTATION_TYPE_ALIASES:
        return IMPLEMENTATION_TYPE_ALIASES[text], None
    if text in ALLOWED_IMPLEMENTATION_TYPES:
        return text, None
    return "unknown", f"Unknown implementation type '{value}' mapped to unknown"


def _normalize_intune_area(
    value: Any, implementation_type: str
) -> tuple[str, str | None]:
    text = _clean_text(value).lower()
    if text in AREA_ALIASES:
        return AREA_ALIASES[text], None
    if implementation_type in ALLOWED_INTUNE_AREAS:
        return ALLOWED_INTUNE_AREAS[
            implementation_type
        ], f"Unknown intune area '{value}' normalized from implementation type"
    return "Manual Review", f"Unknown intune area '{value}' mapped to Manual Review"


def _looks_like_free_text_value(value: str) -> bool:
    if not value:
        return True

    low = value.lower()

    heuristic_markers = [
        "ensure ",
        "review ",
        "compliant if ",
        "secure ",
        "must be ",
        "should be ",
        "verify ",
        "manual ",
        "owner read/write",
        "organization",
        "organizational",
        "pii",
    ]

    if any(marker in low for marker in heuristic_markers):
        return True

    return len(value) > 120


def normalize_suggestion_dict(raw: dict[str, Any]) -> NormalizedSuggestion:
    notes: list[str] = []

    impl, impl_note = _normalize_implementation_type(
        raw.get("suggested_implementation_type")
    )
    if impl_note:
        notes.append(impl_note)

    area, area_note = _normalize_intune_area(raw.get("suggested_intune_area"), impl)
    if area_note:
        notes.append(area_note)

    setting_name = _clean_text(raw.get("suggested_setting_name"))
    if not setting_name:
        setting_name = "Manual review required"
        notes.append("Empty suggested_setting_name replaced with default")

    suggested_value = _clean_text(raw.get("suggested_value"))
    confidence = _normalize_confidence(raw.get("confidence"))
    reasoning = _clean_text(raw.get("reasoning"))

    needs_validation = False

    if impl == "unknown":
        needs_validation = True
        notes.append("Implementation method is unknown")

    if _looks_like_free_text_value(suggested_value):
        needs_validation = True
        notes.append(
            "Suggested value looks like analyst text instead of a deployable setting value"
        )

    if confidence < 0.70:
        needs_validation = True
        notes.append(f"Low confidence: {confidence:.2f}")

    return NormalizedSuggestion(
        suggested_implementation_type=impl,
        suggested_intune_area=area,
        suggested_setting_name=setting_name,
        suggested_value=suggested_value,
        confidence=confidence,
        reasoning=reasoning,
        suggested_catalog_identifier=(
            _clean_text(raw.get("suggested_catalog_identifier")) or None
        ),
        mapping_source=_clean_text(raw.get("candidate_source")) or "llm",
        needs_validation=needs_validation,
        normalization_notes=notes,
    )


def normalize_suggestions(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []

    for record in records:
        core = {
            "cis_id": record.get("cis_id", ""),
            "title": record.get("title", ""),
        }

        ns = normalize_suggestion_dict(record)
        mapping_status = str(record.get("mapping_status", "candidate"))

        normalized.append(
            {
                **core,
                "suggested_implementation_type": ns.suggested_implementation_type,
                "suggested_intune_area": ns.suggested_intune_area,
                "suggested_setting_name": ns.suggested_setting_name,
                "suggested_value": ns.suggested_value,
                "confidence": ns.confidence,
                "reasoning": ns.reasoning,
                "suggested_catalog_identifier": ns.suggested_catalog_identifier,
                "mapping_source": ns.mapping_source,
                "mapping_status": mapping_status,
                "verification": record.get("verification", {}),
                "needs_validation": (
                    ns.needs_validation or mapping_status != "verified"
                ),
                "normalization_notes": "; ".join(ns.normalization_notes),
            }
        )

    return normalized

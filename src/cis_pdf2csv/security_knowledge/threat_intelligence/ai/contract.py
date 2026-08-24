from __future__ import annotations

from hashlib import sha256

from pydantic import Field

from .policy import DEFAULT_AI_INTERPRETATION_POLICY
from .schema import DeterministicModel


class AIThreatInterpretationContract(DeterministicModel):
    contract_id: str = "AI-THREAT-INTERPRETATION"
    contract_version: str = "1.0"
    schema_version: str = "1.0"
    prompt_id: str = "THREAT-INTERPRETATION-JSON"
    prompt_version: str = "1.0"
    allowed_output_schema: str = "ProposedThreatInterpretation"
    authority_policy_version: str = DEFAULT_AI_INTERPRETATION_POLICY.policy_version
    max_input_size: int = Field(default=200_000, gt=0)
    prohibited_output_fields: tuple[str, ...] = (
        DEFAULT_AI_INTERPRETATION_POLICY.prohibited_output_fields
    )
    required_evidence_behavior: tuple[str, ...] = (
        "Every material assertion references supplied input evidence.",
        "Active exploitation and affected technology require explicit evidence.",
        "External model knowledge is prohibited.",
    )
    fail_closed_rules: tuple[str, ...] = (
        "Reject forbidden decision fields.",
        "Reject malformed or unknown catalog identifiers.",
        "Do not convert without explicit human approval.",
    )
    json_only: bool = True
    markdown_allowed: bool = False


DEFAULT_AI_THREAT_INTERPRETATION_CONTRACT = AIThreatInterpretationContract()


def content_hash(content: str) -> str:
    return sha256(content.encode("utf-8")).hexdigest()


def build_document_id(authority: str, stable_key: str) -> str:
    return _stable_id("AIDOC", authority, stable_key)


def build_interpretation_id(
    document_id: str,
    model_provider: str,
    model_name: str,
    contract_id: str,
    stable_key: str,
) -> str:
    return _stable_id(
        "AIINT",
        document_id,
        model_provider,
        model_name,
        contract_id,
        stable_key,
    )


def _stable_id(prefix: str, *parts: str) -> str:
    if any(not part.strip() for part in parts):
        raise ValueError("deterministic identity components must be non-empty")
    digest = sha256("\x00".join(part.strip() for part in parts).encode()).hexdigest()
    return f"{prefix}-{digest[:20].upper()}"


__all__ = [
    "DEFAULT_AI_THREAT_INTERPRETATION_CONTRACT",
    "AIThreatInterpretationContract",
    "build_document_id",
    "build_interpretation_id",
    "content_hash",
]

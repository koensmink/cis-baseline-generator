"""Isolated, provider-neutral contract for untrusted AI threat proposals."""

from .approval import (
    InterpretationApprovalError,
    build_threat_context_from_approved_interpretation,
    validate_interpretation_approval,
)
from .contract import (
    DEFAULT_AI_THREAT_INTERPRETATION_CONTRACT,
    AIThreatInterpretationContract,
    build_document_id,
    build_interpretation_id,
    content_hash,
)
from .policy import DEFAULT_AI_INTERPRETATION_POLICY, AIInterpretationPolicy
from .provenance import AdvisoryDocumentProvenance, AIInterpretationProvenance
from .schema import (
    AdvisoryContentFormat,
    AIContractFinding,
    AIContractFindingSeverity,
    ApprovalModification,
    ApprovalStatus,
    EvidenceSupportType,
    InterpretationEvidenceAssertion,
    InterpretationValidationResult,
    ProposedThreatInterpretation,
    ThreatActivityState,
    ThreatAdvisoryDocument,
    ThreatInterpretationApproval,
)
from .validation import (
    validate_advisory_document,
    validate_interpretation,
    validate_interpretation_payload,
)

__all__ = [
    "DEFAULT_AI_INTERPRETATION_POLICY",
    "DEFAULT_AI_THREAT_INTERPRETATION_CONTRACT",
    "AIContractFinding",
    "AIContractFindingSeverity",
    "AIInterpretationPolicy",
    "AIInterpretationProvenance",
    "AIThreatInterpretationContract",
    "AdvisoryContentFormat",
    "AdvisoryDocumentProvenance",
    "ApprovalModification",
    "ApprovalStatus",
    "EvidenceSupportType",
    "InterpretationApprovalError",
    "InterpretationEvidenceAssertion",
    "InterpretationValidationResult",
    "ProposedThreatInterpretation",
    "ThreatActivityState",
    "ThreatAdvisoryDocument",
    "ThreatInterpretationApproval",
    "build_document_id",
    "build_interpretation_id",
    "build_threat_context_from_approved_interpretation",
    "content_hash",
    "validate_advisory_document",
    "validate_interpretation",
    "validate_interpretation_approval",
    "validate_interpretation_payload",
]

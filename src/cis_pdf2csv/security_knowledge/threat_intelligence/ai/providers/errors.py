from __future__ import annotations

from ..schema import (
    AIContractFinding,
    DeterministicModel,
    EvidenceAssertionType,
    EvidenceSupportType,
)


class EvidenceBindingDiagnostic(DeterministicModel):
    assertion_id: str
    assertion_type: EvidenceAssertionType
    value: str
    source_locator: str
    support_type: EvidenceSupportType
    explicitly_stated: bool
    inference_required: bool


class AIProviderError(RuntimeError):
    code = "AI_PROVIDER_ERROR"
    exit_code = 3
    retryable = False

    def __init__(self, message: str) -> None:
        super().__init__(f"{self.code}: {message}")


class ProviderConfigurationError(AIProviderError):
    code = "AI_PROVIDER_CONFIGURATION_ERROR"
    exit_code = 2


class MissingCredentialError(ProviderConfigurationError):
    code = "AI_PROVIDER_MISSING_CREDENTIAL"


class ProviderInputError(AIProviderError):
    code = "AI_PROVIDER_INPUT_ERROR"
    exit_code = 2


class ProviderInputTooLargeError(ProviderInputError):
    code = "AI_PROVIDER_INPUT_TOO_LARGE"


class ProviderAuthenticationError(AIProviderError):
    code = "AI_PROVIDER_AUTHENTICATION_FAILED"


class ProviderTimeoutError(AIProviderError):
    code = "AI_PROVIDER_TIMEOUT"
    retryable = True


class ProviderRateLimitError(AIProviderError):
    code = "AI_PROVIDER_RATE_LIMITED"
    retryable = True


class ProviderTransientError(AIProviderError):
    code = "AI_PROVIDER_TRANSIENT_FAILURE"
    retryable = True


class InvalidStructuredOutputError(AIProviderError):
    code = "AI_PROVIDER_INVALID_STRUCTURED_OUTPUT"
    exit_code = 4


class ProviderSchemaMismatchError(InvalidStructuredOutputError):
    code = "AI_PROVIDER_SCHEMA_MISMATCH"


class ProviderContractValidationError(AIProviderError):
    code = "AI_PROVIDER_CONTRACT_VALIDATION_FAILED"
    exit_code = 4

    def __init__(
        self,
        message: str,
        *,
        findings: tuple[AIContractFinding, ...] = (),
        evidence_bindings: tuple[EvidenceBindingDiagnostic, ...] = (),
        material_values: tuple[str, ...] = (),
    ) -> None:
        self.findings = findings
        self.evidence_bindings = evidence_bindings
        self.material_values = material_values
        details = "; ".join(
            f"{finding.code}: {finding.message}"
            for finding in findings
            if finding.blocking
        )
        super().__init__(f"{message}: {details}" if details else message)


class UnsupportedModelError(ProviderConfigurationError):
    code = "AI_PROVIDER_UNSUPPORTED_MODEL"


__all__ = [
    "AIProviderError",
    "EvidenceBindingDiagnostic",
    "InvalidStructuredOutputError",
    "MissingCredentialError",
    "ProviderAuthenticationError",
    "ProviderConfigurationError",
    "ProviderContractValidationError",
    "ProviderInputError",
    "ProviderInputTooLargeError",
    "ProviderRateLimitError",
    "ProviderSchemaMismatchError",
    "ProviderTimeoutError",
    "ProviderTransientError",
    "UnsupportedModelError",
]

from __future__ import annotations

import json
import os
from datetime import datetime
from hashlib import sha256
from typing import Any, Protocol

from openai import OpenAIError
from pydantic import ValidationError

from ....catalog.registry import SecurityKnowledgeCatalog
from ....provenance import Confidence
from ...schema import ThreatApplicabilityScope, ThreatSeverity
from ..contract import AIThreatInterpretationContract, build_interpretation_id
from ..policy import DEFAULT_AI_INTERPRETATION_POLICY, AIInterpretationPolicy
from ..provenance import AIInterpretationProvenance
from ..schema import (
    AIContractFindingSeverity,
    DeterministicModel,
    InterpretationEvidenceAssertion,
    ProposedThreatInterpretation,
    ThreatActivityState,
    ThreatAdvisoryDocument,
)
from ..validation import (
    required_evidence_bindings,
    validate_advisory_document,
    validate_interpretation,
    validate_interpretation_payload,
)
from .base import ProviderInterpretationResult, ProviderWarning
from .config import OpenAIProviderConfig
from .errors import (
    AIProviderError,
    EvidenceBindingDiagnostic,
    InvalidStructuredOutputError,
    MissingCredentialError,
    ProviderAuthenticationError,
    ProviderContractValidationError,
    ProviderInputError,
    ProviderInputTooLargeError,
    ProviderRateLimitError,
    ProviderSchemaMismatchError,
    ProviderTimeoutError,
    ProviderTransientError,
    UnsupportedModelError,
)
from .prompt import build_provider_messages, catalog_vocabulary, vocabulary_hash


class ProviderProposalPayload(DeterministicModel):
    title: str
    summary: str
    observed_at: datetime | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    proposed_confidence: Confidence
    proposed_severity: ThreatSeverity
    proposed_activity_state: ThreatActivityState
    proposed_threat_scenario_ids: tuple[str, ...] = ()
    proposed_technique_ids: tuple[str, ...] = ()
    proposed_attack_path_ids: tuple[str, ...] = ()
    proposed_affected_technology_families: tuple[str, ...] = ()
    proposed_targeted_asset_classes: tuple[str, ...] = ()
    proposed_applicability_scope: ThreatApplicabilityScope
    evidence_assertions: tuple[InterpretationEvidenceAssertion, ...]
    uncertainty_notes: tuple[str, ...] = ()
    unsupported_claims: tuple[str, ...] = ()


class ResponsesClient(Protocol):
    @property
    def responses(self) -> Any: ...


class OpenAIThreatInterpretationProvider:
    provider_name = "openai"

    def __init__(
        self,
        config: OpenAIProviderConfig,
        *,
        api_key: str | None = None,
        client: ResponsesClient | None = None,
        policy: AIInterpretationPolicy = DEFAULT_AI_INTERPRETATION_POLICY,
    ) -> None:
        self.config = config
        self.policy = policy
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if client is None and not self._api_key:
            raise MissingCredentialError("OPENAI_API_KEY or an explicit runtime key is required")
        self._client = client

    def build_request(
        self,
        document: ThreatAdvisoryDocument,
        contract: AIThreatInterpretationContract,
        catalog: SecurityKnowledgeCatalog,
    ) -> dict[str, Any]:
        vocabulary = catalog_vocabulary(catalog)
        request: dict[str, Any] = {
            "model": self.config.model,
            "input": list(build_provider_messages(document, contract, self.policy, vocabulary)),
            "max_output_tokens": self.config.max_output_tokens,
            "store": False,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "proposed_threat_interpretation",
                    "strict": True,
                    "schema": _strict_json_schema(
                        ProviderProposalPayload.model_json_schema()
                    ),
                }
            },
            "timeout": self.config.timeout_seconds,
        }
        if self.config.temperature is not None:
            request["temperature"] = self.config.temperature
        if self.config.top_p is not None:
            request["top_p"] = self.config.top_p
        return request

    def interpret(
        self,
        document: ThreatAdvisoryDocument,
        contract: AIThreatInterpretationContract,
        catalog: SecurityKnowledgeCatalog,
    ) -> ProviderInterpretationResult:
        preflight = validate_advisory_document(document)
        blocking = [item for item in preflight if item.blocking]
        sensitive_codes = {"AI_INPUT_POTENTIAL_SECRET", "AI_INPUT_PERSONAL_DATA"}
        if not self.config.privacy_policy.sensitive_data_allowed:
            blocking.extend(item for item in preflight if item.code in sensitive_codes)
        if blocking:
            raise ProviderInputError("local advisory preflight blocked provider invocation")
        if len(document.content.encode("utf-8")) > contract.max_input_size:
            raise ProviderInputTooLargeError("advisory exceeds the deterministic contract input limit")
        client = self._client or self._create_client()
        request = self.build_request(document, contract, catalog)
        response = self._request_with_retries(client, request)
        raw_text = getattr(response, "output_text", None)
        if not isinstance(raw_text, str) or not raw_text.strip():
            raise InvalidStructuredOutputError("provider response contained no structured output")
        if raw_text.lstrip().startswith("```"):
            raise InvalidStructuredOutputError("Markdown responses are not accepted")
        try:
            raw_payload = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise InvalidStructuredOutputError("provider output was not strict JSON") from exc
        if not isinstance(raw_payload, dict):
            raise ProviderSchemaMismatchError("provider output must be a JSON object")
        forbidden = set(raw_payload) & set(self.policy.prohibited_output_fields)
        if forbidden:
            raise ProviderContractValidationError(
                f"forbidden provider output fields: {', '.join(sorted(forbidden))}"
            )
        try:
            payload = ProviderProposalPayload.model_validate(raw_payload)
        except ValidationError as exc:
            raise ProviderSchemaMismatchError(
                f"provider output failed schema validation ({exc.error_count()} error(s))"
            ) from exc
        raw_hash = sha256(raw_text.encode()).hexdigest()
        interpretation = self._to_interpretation(payload, document, contract, raw_hash)
        parsed, payload_findings = validate_interpretation_payload(
            interpretation.model_dump(mode="json"), policy=self.policy
        )
        if parsed is None or any(item.blocking for item in payload_findings):
            raise ProviderContractValidationError(
                "Phase 4A authority validation rejected provider output",
                findings=payload_findings,
                evidence_bindings=_evidence_diagnostics(interpretation),
            )
        validation = validate_interpretation(
            parsed,
            document,
            catalog,
            policy=self.policy,
            contract=contract,
        )
        if validation.blocking:
            raise ProviderContractValidationError(
                "Phase 4A contract validation blocked the proposed interpretation",
                findings=validation.findings,
                evidence_bindings=_evidence_diagnostics(parsed),
                material_values=tuple(
                    f"{kind}={value}" for kind, value in required_evidence_bindings(parsed)
                ),
            )
        vocabulary = catalog_vocabulary(catalog)
        return ProviderInterpretationResult(
            provider=self.provider_name,
            model=self.config.model,
            model_version=getattr(response, "model", None),
            request_id=getattr(response, "id", None),
            contract_id=contract.contract_id,
            contract_version=contract.contract_version,
            prompt_id=contract.prompt_id,
            prompt_version=contract.prompt_version,
            document_id=document.document_id,
            document_hash=document.content_hash,
            catalog_version=catalog.catalog_version,
            catalog_vocabulary_hash=vocabulary_hash(vocabulary),
            generation_parameter_identity=self.config.generation_parameter_identity(),
            raw_response_hash=raw_hash,
            interpretation=parsed,
            validation=validation,
            provider_warnings=tuple(
                ProviderWarning(code=item.code, message=item.message)
                for item in preflight
                if item.severity != AIContractFindingSeverity.ERROR
            ),
            preflight_findings=preflight,
        )

    def _to_interpretation(
        self,
        payload: ProviderProposalPayload,
        document: ThreatAdvisoryDocument,
        contract: AIThreatInterpretationContract,
        raw_hash: str,
    ) -> ProposedThreatInterpretation:
        identity = build_interpretation_id(
            document.document_id,
            self.provider_name,
            self.config.model,
            contract.contract_id,
            self.config.generation_parameter_identity(),
        )
        return ProposedThreatInterpretation(
            interpretation_id=identity,
            interpretation_revision=raw_hash[:16],
            schema_version=contract.schema_version,
            model_provider=self.provider_name,
            model_name=self.config.model,
            model_version=self.config.model,
            prompt_id=contract.prompt_id,
            prompt_version=contract.prompt_version,
            generated_at=self.config.generated_at,
            input_document_id=document.document_id,
            input_hash=document.content_hash,
            title=payload.title,
            summary=payload.summary,
            source_type=document.source_type,
            source_name=document.source_name,
            source_reference=document.source_reference,
            published_at=document.published_at,
            observed_at=payload.observed_at,
            valid_from=payload.valid_from,
            valid_until=payload.valid_until,
            proposed_confidence=payload.proposed_confidence,
            proposed_severity=payload.proposed_severity,
            proposed_activity_state=payload.proposed_activity_state,
            proposed_threat_scenario_ids=payload.proposed_threat_scenario_ids,
            proposed_technique_ids=payload.proposed_technique_ids,
            proposed_attack_path_ids=payload.proposed_attack_path_ids,
            proposed_affected_technology_families=payload.proposed_affected_technology_families,
            proposed_targeted_asset_classes=payload.proposed_targeted_asset_classes,
            proposed_applicability_scope=payload.proposed_applicability_scope,
            evidence_assertions=payload.evidence_assertions,
            uncertainty_notes=payload.uncertainty_notes,
            unsupported_claims=payload.unsupported_claims,
            provenance=AIInterpretationProvenance(
                contract_id=contract.contract_id,
                contract_version=contract.contract_version,
                authority_policy_version=self.policy.policy_version,
                generation_parameters_id=self.config.generation_parameter_identity(),
                input_document_hash=document.content_hash,
            ),
        )

    def _create_client(self) -> ResponsesClient:
        from openai import OpenAI

        return OpenAI(
            api_key=self._api_key,
            organization=self.config.organization,
            project=self.config.project,
            timeout=self.config.timeout_seconds,
            max_retries=0,
        )

    def _request_with_retries(self, client: ResponsesClient, request: dict[str, Any]) -> Any:
        for attempt in range(self.config.max_retries + 1):
            try:
                return client.responses.create(**request)
            except OpenAIError as exc:
                mapped = _map_provider_error(exc)
                if not mapped.retryable or attempt >= self.config.max_retries:
                    raise mapped from None
        raise AssertionError("bounded retry loop exhausted")


def _map_provider_error(error: Exception) -> AIProviderError:
    name = type(error).__name__.lower()
    if "authentication" in name or "permission" in name:
        return ProviderAuthenticationError("provider rejected authentication")
    if "ratelimit" in name or "rate_limit" in name:
        return ProviderRateLimitError("provider rate limit reached")
    if "timeout" in name:
        return ProviderTimeoutError("provider request timed out")
    if "connection" in name or "internalserver" in name or "serviceunavailable" in name:
        return ProviderTransientError("provider service temporarily unavailable")
    if "badrequest" in name or "unsupported" in name:
        return UnsupportedModelError(
            "model or endpoint does not support the required structured-output contract"
        )
    return ProviderTransientError("provider request failed")


def _evidence_diagnostics(
    interpretation: ProposedThreatInterpretation,
) -> tuple[EvidenceBindingDiagnostic, ...]:
    return tuple(
        EvidenceBindingDiagnostic(
            assertion_id=item.assertion_id,
            assertion_type=item.assertion_type,
            value=item.value,
            source_locator=item.source_locator,
            support_type=item.support_type,
            explicitly_stated=item.explicitly_stated,
            inference_required=item.inference_required,
        )
        for item in sorted(
            interpretation.evidence_assertions,
            key=lambda value: value.assertion_id,
        )
    )


def _strict_json_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Make Pydantic's schema conform to strict structured-output requirements."""
    value = json.loads(json.dumps(schema, sort_keys=True))

    def visit(item: object) -> None:
        if isinstance(item, dict):
            properties = item.get("properties")
            if item.get("type") == "object" and isinstance(properties, dict):
                item["additionalProperties"] = False
                item["required"] = sorted(properties)
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return value


__all__ = ["OpenAIThreatInterpretationProvider", "ProviderProposalPayload"]

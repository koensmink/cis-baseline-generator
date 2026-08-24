from __future__ import annotations

import json
from datetime import datetime
from hashlib import sha256
from typing import Literal

from pydantic import Field, model_validator

from ..schema import DeterministicModel


class ProviderPrivacyPolicy(DeterministicModel):
    policy_id: str = "AI-PROVIDER-PRIVACY-DEFAULT"
    provider_name: str = "openai"
    intended_processing_region: str | None = None
    retention_policy_id: str | None = None
    training_use_permitted: bool = False
    sensitive_data_allowed: bool = False
    customer_data_allowed: bool = False


class OpenAIProviderConfig(DeterministicModel):
    provider: Literal["openai"] = "openai"
    model: str = Field(min_length=1)
    generated_at: datetime
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    max_retries: int = Field(default=1, ge=0, le=3)
    temperature: float | None = Field(default=0.0, ge=0, le=2)
    top_p: float | None = Field(default=None, gt=0, le=1)
    max_output_tokens: int = Field(default=8_000, gt=0, le=100_000)
    response_schema_mode: Literal["json_schema"] = "json_schema"
    organization: str | None = None
    project: str | None = None
    privacy_policy: ProviderPrivacyPolicy = ProviderPrivacyPolicy()

    @model_validator(mode="after")
    def sampling_is_unambiguous(self) -> OpenAIProviderConfig:
        if self.temperature is not None and self.top_p is not None:
            raise ValueError("configure temperature or top_p, not both")
        if self.generated_at.tzinfo is None or self.generated_at.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        return self

    def generation_parameter_identity(self) -> str:
        payload = {
            "max_output_tokens": self.max_output_tokens,
            "model": self.model,
            "response_schema_mode": self.response_schema_mode,
            "temperature": self.temperature,
            "top_p": self.top_p,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return f"GEN-{sha256(encoded).hexdigest()[:20].upper()}"


__all__ = ["OpenAIProviderConfig", "ProviderPrivacyPolicy"]

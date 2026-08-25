from __future__ import annotations

from enum import Enum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import ImplementationMethod


class CatalogValueType(str, Enum):
    BOOLEAN = "boolean"
    INTEGER = "integer"
    RANGE = "range"
    ENUM = "enum"
    TEXT = "text"


class CatalogProvenance(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: str = Field(min_length=1)
    catalog_version: str = Field(min_length=1)
    authoritative_for_scope: bool = False
    notes: str = Field(min_length=1)


class AuthoritativeCatalogEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    canonical_identifier: str = Field(min_length=1)
    implementation_method: ImplementationMethod
    policy_type: str | None = None
    category: str | None = None
    setting_name: str = Field(min_length=1)
    setting_definition_id: str | None = None
    endpoint_security_template_id: str | None = None
    endpoint_security_setting_id: str | None = None
    csp_uri: str | None = None
    value_type: CatalogValueType
    allowed_enum_values: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None
    assignment_scope: str | None = None
    supported_platforms: tuple[str, ...] = ()
    supported_os_versions: tuple[str, ...] = ()
    provenance: CatalogProvenance

    @model_validator(mode="after")
    def validate_method_specific_metadata(self) -> AuthoritativeCatalogEntry:
        if (
            self.implementation_method == ImplementationMethod.SETTINGS_CATALOG
            and not self.setting_definition_id
        ):
            raise ValueError("Settings Catalog entries require a definition ID")
        if (
            self.implementation_method == ImplementationMethod.ENDPOINT_SECURITY
            and not (
                self.endpoint_security_template_id or self.endpoint_security_setting_id
            )
        ):
            raise ValueError(
                "Endpoint Security entries require a template or setting ID"
            )
        if (
            self.implementation_method
            in {
                ImplementationMethod.POLICY_CSP,
                ImplementationMethod.CUSTOM_OMA_URI,
            }
            and not self.csp_uri
        ):
            raise ValueError("CSP-based entries require a CSP URI")
        if self.value_type == CatalogValueType.ENUM and not self.allowed_enum_values:
            raise ValueError("Enum entries require allowed values")
        if (
            self.minimum is not None
            and self.maximum is not None
            and self.minimum > self.maximum
        ):
            raise ValueError("Catalog minimum cannot exceed maximum")
        return self


class AuthoritativeCatalog(Protocol):
    @property
    def source(self) -> str: ...

    @property
    def version(self) -> str: ...

    def find_by_identifier(
        self, identifier: str
    ) -> tuple[AuthoritativeCatalogEntry, ...]: ...


class LocalAuthoritativeCatalog:
    """Small deterministic catalog; not a complete Microsoft metadata snapshot."""

    def __init__(
        self,
        entries: tuple[AuthoritativeCatalogEntry, ...],
        *,
        source: str,
        version: str,
    ) -> None:
        self._entries = tuple(
            sorted(entries, key=lambda item: item.canonical_identifier)
        )
        self._source = source
        self._version = version

    @property
    def source(self) -> str:
        return self._source

    @property
    def version(self) -> str:
        return self._version

    def find_by_identifier(
        self, identifier: str
    ) -> tuple[AuthoritativeCatalogEntry, ...]:
        return tuple(
            item for item in self._entries if item.canonical_identifier == identifier
        )


_LIMITED_PROVENANCE = CatalogProvenance(
    source="repository_local_authoritative_catalog",
    catalog_version="local-test-v1",
    authoritative_for_scope=True,
    notes=(
        "Repository-maintained limited fixture for deterministic verification tests; "
        "not a complete or current Microsoft Intune metadata export."
    ),
)

DEFAULT_LOCAL_CATALOG = LocalAuthoritativeCatalog(
    (
        AuthoritativeCatalogEntry(
            canonical_identifier="local.windows_server_2025.defender.antivirus_enabled",
            implementation_method=ImplementationMethod.ENDPOINT_SECURITY,
            policy_type="endpoint_security_antivirus",
            category="Defender Security",
            setting_name="Microsoft Defender Antivirus",
            endpoint_security_setting_id=(
                "local_fixture.windows_server_2025.defender.antivirus_enabled"
            ),
            value_type=CatalogValueType.BOOLEAN,
            assignment_scope="device",
            supported_platforms=("windows_server_2025",),
            supported_os_versions=("Windows Server 2025",),
            provenance=_LIMITED_PROVENANCE,
        ),
    ),
    source="repository_local_authoritative_catalog",
    version="local-test-v1",
)


__all__ = [
    "DEFAULT_LOCAL_CATALOG",
    "AuthoritativeCatalog",
    "AuthoritativeCatalogEntry",
    "CatalogProvenance",
    "CatalogValueType",
    "LocalAuthoritativeCatalog",
]

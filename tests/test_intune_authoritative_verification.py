from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from cis_pdf2csv.intune_mapper.catalog import (
    AuthoritativeCatalogEntry,
    CatalogProvenance,
    CatalogValueType,
    LocalAuthoritativeCatalog,
)
from cis_pdf2csv.intune_mapper.cli import main as intune_main
from cis_pdf2csv.intune_mapper.exporters import (
    write_baseline_csv,
    write_intune_policies_json,
    write_manual_review_csv,
)
from cis_pdf2csv.intune_mapper.models import (
    CandidateSource,
    ImplementationMethod,
    MappingCandidate,
    MappingInputControl,
    MappingStatus,
)
from cis_pdf2csv.intune_mapper.normalizer import normalize_control
from cis_pdf2csv.intune_mapper.resolver import resolve_control, resolve_controls
from cis_pdf2csv.intune_mapper.suggestion_normalizer import normalize_suggestion_dict
from cis_pdf2csv.intune_mapper.value_parser import parse_recommendation
from cis_pdf2csv.intune_mapper.verifier import AuthoritativeCatalogResolver


def provenance(*, authoritative: bool = True) -> CatalogProvenance:
    return CatalogProvenance(
        source="synthetic_local_catalog",
        catalog_version="test-v1",
        authoritative_for_scope=authoritative,
        notes="Invented metadata used only by tests.",
    )


def entry(
    identifier: str = "TEST-SETTING-1",
    *,
    method: ImplementationMethod = ImplementationMethod.SETTINGS_CATALOG,
    value_type: CatalogValueType = CatalogValueType.BOOLEAN,
    allowed: tuple[str, ...] = (),
    minimum: int | None = None,
    maximum: int | None = None,
    platforms: tuple[str, ...] = ("windows_server_2025",),
    authoritative: bool = True,
) -> AuthoritativeCatalogEntry:
    return AuthoritativeCatalogEntry(
        canonical_identifier=identifier,
        implementation_method=method,
        policy_type="configuration_policy",
        category="Synthetic Area",
        setting_name="Synthetic Setting",
        setting_definition_id=(
            "synthetic-definition"
            if method == ImplementationMethod.SETTINGS_CATALOG
            else None
        ),
        endpoint_security_setting_id=(
            "synthetic-endpoint-setting"
            if method == ImplementationMethod.ENDPOINT_SECURITY
            else None
        ),
        csp_uri=(
            "./Device/Vendor/MSFT/Policy/Config/Synthetic/Setting"
            if method
            in {ImplementationMethod.POLICY_CSP, ImplementationMethod.CUSTOM_OMA_URI}
            else None
        ),
        value_type=value_type,
        allowed_enum_values=allowed,
        minimum=minimum,
        maximum=maximum,
        assignment_scope="device",
        supported_platforms=platforms,
        supported_os_versions=("Synthetic OS",),
        provenance=provenance(authoritative=authoritative),
    )


def catalog(*entries: AuthoritativeCatalogEntry) -> LocalAuthoritativeCatalog:
    return LocalAuthoritativeCatalog(
        tuple(entries), source="synthetic_local_catalog", version="test-v1"
    )


def candidate(
    *,
    value: str = "Enabled",
    method: ImplementationMethod = ImplementationMethod.SETTINGS_CATALOG,
    source: CandidateSource = CandidateSource.DETERMINISTIC_RULE,
    identifier: str | None = "TEST-SETTING-1",
    target: str | None = "windows_server_2025",
    confidence: float = 0.82,
) -> MappingCandidate:
    control = normalize_control(
        MappingInputControl(
            benchmark_family="microsoft-windows-server",
            benchmark_name="Invented Windows benchmark",
            benchmark_version="test-v1",
            profile="L1",
            control_id="1.2.3",
            title="Invented setting",
            recommendation=value,
        )
    )
    return MappingCandidate(
        source_identity=control.source_identity,
        recommendation_id=control.control_id,
        title=control.title,
        target_platform=target,
        implementation_method=method,
        proposed_intune_area="Synthetic Area",
        proposed_setting_name="Synthetic Setting",
        proposed_value=value,
        candidate_source=source,
        candidate_confidence=confidence,
        catalog_identifier=identifier,
        rule_id="synthetic.rule",
        reasoning="Invented deterministic evidence.",
        parsed_recommendation=parse_recommendation(value),
    )


def reason_codes(result) -> set[str]:  # type: ignore[no-untyped-def]
    return set(result.verification.reason_codes)


def test_exact_identifier_valid_value_and_platform_is_verified() -> None:
    result = AuthoritativeCatalogResolver(catalog(entry())).verify(candidate())
    assert result.mapping_status == MappingStatus.VERIFIED
    assert result.value is True
    assert result.verification.match_method == "exact_identifier"
    assert result.verification.reason_codes == ()


def test_llm_confidence_cannot_create_verification() -> None:
    result = AuthoritativeCatalogResolver(catalog(entry())).verify(
        candidate(source=CandidateSource.LLM, confidence=1.0, identifier="MISSING")
    )
    assert result.mapping_status == MappingStatus.UNVERIFIED
    assert reason_codes(result) == {
        "CATALOG_ENTRY_NOT_FOUND",
        "LLM_CANDIDATE_UNVERIFIED",
    }


def test_llm_exact_catalog_match_still_cannot_self_verify() -> None:
    result = AuthoritativeCatalogResolver(catalog(entry())).verify(
        candidate(source=CandidateSource.LLM, confidence=1.0)
    )
    assert result.mapping_status == MappingStatus.UNVERIFIED
    assert reason_codes(result) == {"LLM_CANDIDATE_UNVERIFIED"}


def test_llm_suggestion_pipeline_uses_verifier_and_remains_unverified() -> None:
    class ExactCatalogClient:
        def suggest_mapping(self, mapping):  # type: ignore[no-untyped-def]
            return self.suggest_mappings_batch([mapping])[0]

        def suggest_mappings_batch(self, mappings):  # type: ignore[no-untyped-def]
            return [
                {
                    "suggested_implementation_type": "endpoint_security",
                    "suggested_intune_area": "Defender Security",
                    "suggested_setting_name": "Microsoft Defender Antivirus",
                    "suggested_catalog_identifier": (
                        "local.windows_server_2025.defender.antivirus_enabled"
                    ),
                    "suggested_value": "Enabled",
                    "confidence": 1.0,
                    "reasoning": "Invented exact catalog proposal.",
                }
                for _ in mappings
            ]

    result = resolve_controls(
        [
            MappingInputControl(
                benchmark_name="CIS Microsoft Windows Server 2025 Benchmark",
                benchmark_version="1.0",
                profile="L1",
                control_id="9.9",
                title="Invented unsupported preference",
                recommendation="Enabled",
            )
        ],
        llm_client=ExactCatalogClient(),
    )
    assert result.mappings[0].mapping_status == MappingStatus.MANUAL_REVIEW
    assert result.suggestions[0].mapping_status == MappingStatus.UNVERIFIED
    assert result.suggestions[0].candidate_source == CandidateSource.LLM
    assert result.suggestions[0].verification.reason_codes == (
        "LLM_CANDIDATE_UNVERIFIED",
    )


def test_invalid_value_and_method_do_not_verify() -> None:
    resolver = AuthoritativeCatalogResolver(catalog(entry()))
    invalid_value = resolver.verify(candidate(value="not-a-boolean"))
    wrong_method = resolver.verify(
        candidate(method=ImplementationMethod.ENDPOINT_SECURITY)
    )
    assert "VALUE_TYPE_MISMATCH" in reason_codes(invalid_value)
    assert "IMPLEMENTATION_METHOD_MISMATCH" in reason_codes(wrong_method)
    assert invalid_value.mapping_status == MappingStatus.UNVERIFIED
    assert wrong_method.mapping_status == MappingStatus.UNVERIFIED


def test_unsupported_platform_does_not_verify() -> None:
    result = AuthoritativeCatalogResolver(catalog(entry())).verify(
        candidate(target="windows_server_2022")
    )
    assert result.mapping_status == MappingStatus.UNVERIFIED
    assert "PLATFORM_NOT_SUPPORTED" in reason_codes(result)


def test_enum_and_integer_constraints_are_authoritative() -> None:
    enum_result = AuthoritativeCatalogResolver(
        catalog(
            entry(
                value_type=CatalogValueType.ENUM,
                allowed=("allow", "block"),
            )
        )
    ).verify(candidate(value="audit"))
    integer_result = AuthoritativeCatalogResolver(
        catalog(entry(value_type=CatalogValueType.INTEGER, minimum=1, maximum=10))
    ).verify(candidate(value=">= 11"))
    assert "ENUM_VALUE_NOT_ALLOWED" in reason_codes(enum_result)
    assert "VALUE_OUT_OF_RANGE" in reason_codes(integer_result)


def test_not_configured_is_not_disabled() -> None:
    disabled = parse_recommendation("Disabled")
    not_configured = parse_recommendation("Not configured")
    assert disabled.configuration_state == "disabled"
    assert disabled.bool_value is False
    assert not_configured.configuration_state == "not_configured"
    assert not_configured.value_type == "enum"
    assert not_configured.bool_value is None


def test_bounded_expression_preserves_operator() -> None:
    assert parse_recommendation("at least 15").operator == ">="
    assert parse_recommendation("maximum 30").operator == "<="


def test_ambiguous_identifier_is_not_selected() -> None:
    result = AuthoritativeCatalogResolver(catalog(entry(), entry())).verify(candidate())
    assert result.mapping_status == MappingStatus.UNVERIFIED
    assert "AMBIGUOUS_CATALOG_MATCH" in reason_codes(result)


def test_only_verifier_contains_verified_status_assignment() -> None:
    package = Path(__file__).parents[1] / "src/cis_pdf2csv/intune_mapper"
    assignments = []
    for path in package.rglob("*.py"):
        if "status = MappingStatus.VERIFIED" in path.read_text(encoding="utf-8"):
            assignments.append(path.name)
    assert assignments == ["verifier.py"]


def test_broad_deterministic_rule_without_catalog_key_is_unverified() -> None:
    mapping, _ = resolve_control(
        MappingInputControl(
            benchmark_name="CIS Microsoft Windows Server 2025 Benchmark",
            benchmark_version="1.0",
            profile="L1",
            control_id="9.9",
            title="Configure an invented firewall logging preference",
            recommendation="Enabled",
        )
    )
    assert mapping.rule_id == "windows_server_2025.firewall"
    assert mapping.mapping_status == MappingStatus.UNVERIFIED
    assert "CATALOG_ENTRY_NOT_FOUND" in reason_codes(mapping)


def test_exact_bundled_rule_is_verified_but_catalog_is_explicitly_limited() -> None:
    mapping, _ = resolve_control(
        MappingInputControl(
            benchmark_name="CIS Microsoft Windows Server 2025 Benchmark",
            benchmark_version="1.0",
            profile="L1",
            control_id="1.1",
            title="(L1) Ensure Microsoft Defender Antivirus is Enabled",
            recommendation="Enabled",
        )
    )
    assert mapping.mapping_status == MappingStatus.VERIFIED
    assert mapping.platform == "microsoft_intune"
    assert mapping.verification.source == "repository_local_authoritative_catalog"
    assert mapping.verification.catalog_version == "local-test-v1"


def test_conflicts_remain_visible_and_deterministic() -> None:
    control = MappingInputControl(
        benchmark_name="CIS Microsoft Windows Server 2025 Benchmark",
        benchmark_version="1.0",
        profile="L1",
        control_id="9.9",
        title="Configure Microsoft Defender Firewall",
        recommendation="Enabled",
    )
    first, conflict = resolve_control(control)
    second, second_conflict = resolve_control(control)
    assert conflict is not None
    assert first == second
    assert conflict == second_conflict
    assert conflict.matched_rule_ids == [
        "windows_server_2025.defender",
        "windows_server_2025.firewall",
    ]


def test_suggestion_normalization_canonicalizes_script_and_confidence() -> None:
    normalized = normalize_suggestion_dict(
        {
            "suggested_implementation_type": "script",
            "suggested_intune_area": "Scripts",
            "suggested_setting_name": "Invented remediation",
            "suggested_value": "Enabled",
            "confidence": "High",
            "reasoning": "Invented suggestion",
            "candidate_source": "llm",
        }
    )
    assert normalized.suggested_implementation_type == "powershell"
    assert normalized.confidence == 0.85
    assert normalized.mapping_source == "llm"


def test_exporters_separate_status_confidence_and_verification(tmp_path: Path) -> None:
    resolver = AuthoritativeCatalogResolver(catalog(entry()))
    verified = resolver.verify(candidate())
    unverified = resolver.verify(candidate(identifier="MISSING"))
    baseline = tmp_path / "baseline.csv"
    review = tmp_path / "manual_review.csv"
    policies = tmp_path / "intune_policies.json"
    write_baseline_csv((verified, unverified), baseline)
    write_manual_review_csv((verified, unverified), review)
    write_intune_policies_json((verified, unverified), policies)

    with baseline.open(encoding="utf-8-sig", newline="") as handle:
        baseline_rows = list(csv.DictReader(handle))
    with review.open(encoding="utf-8-sig", newline="") as handle:
        review_rows = list(csv.DictReader(handle))
    payload = json.loads(policies.read_text(encoding="utf-8"))
    assert [row["mapping_status"] for row in baseline_rows] == ["verified"]
    assert [row["mapping_status"] for row in review_rows] == ["unverified"]
    assert baseline_rows[0]["candidate_confidence"] == "0.82"
    assert baseline_rows[0]["verification_match_method"] == "exact_identifier"
    settings = payload["policies"][0]["settings"]
    assert len(settings) == 1
    assert settings[0]["mapping_status"] == "verified"


def test_cli_reports_status_categories(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    controls = tmp_path / "controls.jsonl"
    records = [
        MappingInputControl(
            benchmark_name="CIS Microsoft Windows Server 2025 Benchmark",
            benchmark_version="1.0",
            profile="L1",
            control_id="1",
            title="(L1) Ensure Microsoft Defender Antivirus is Enabled",
            recommendation="Enabled",
        ),
        MappingInputControl(
            benchmark_name="CIS Microsoft Windows Server 2025 Benchmark",
            benchmark_version="1.0",
            profile="L1",
            control_id="2",
            title="Configure an invented firewall preference",
            recommendation="Enabled",
        ),
        MappingInputControl(
            benchmark_name="CIS Microsoft Windows Server 2025 Benchmark",
            benchmark_version="1.0",
            profile="L1",
            control_id="3",
            title="Invented unsupported preference",
            recommendation="Custom",
        ),
    ]
    controls.write_text(
        "".join(item.model_dump_json() + "\n" for item in records), encoding="utf-8"
    )
    assert intune_main([str(controls), "-o", str(tmp_path / "out")]) == 0
    output = capsys.readouterr().out
    assert "Verified" in output
    assert "Unverified" in output
    assert "Manual review" in output


def test_insufficient_provenance_cannot_be_overridden_by_confidence() -> None:
    result = AuthoritativeCatalogResolver(catalog(entry(authoritative=False))).verify(
        candidate(confidence=1.0)
    )
    assert result.mapping_status == MappingStatus.UNVERIFIED
    assert "INSUFFICIENT_PROVENANCE" in reason_codes(result)

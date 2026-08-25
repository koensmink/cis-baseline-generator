from __future__ import annotations

from ...models import ImplementationMethod, MappingCandidate, NormalizedControl
from ..base import MappingRule, build_rule_candidate


class DefenderRule(MappingRule):
    rule_id = "windows_server_2025.defender"

    def matches(self, control: NormalizedControl) -> bool:
        t = control.title.lower()
        return "defender" in t or "antivirus" in t

    def apply(self, control: NormalizedControl) -> MappingCandidate:
        title = control.title.casefold().removeprefix("(l1) ")
        catalog_identifier = None
        if title == "ensure microsoft defender antivirus is enabled":
            catalog_identifier = "local.windows_server_2025.defender.antivirus_enabled"
        return build_rule_candidate(
            control,
            rule_id=self.rule_id,
            implementation_method=ImplementationMethod.ENDPOINT_SECURITY,
            intune_area="Defender Security",
            setting_name="Microsoft Defender Antivirus",
            confidence=0.82,
            catalog_identifier=catalog_identifier,
        )

from __future__ import annotations

from ...models import ImplementationMethod, MappingCandidate, NormalizedControl
from ..base import MappingRule, build_rule_candidate


class SecurityOptionsRule(MappingRule):
    rule_id = "windows_server_2025.security_options"

    def matches(self, control: NormalizedControl) -> bool:
        t = control.title.lower()
        return "security option" in t or "consumer experiences" in t

    def apply(self, control: NormalizedControl) -> MappingCandidate:
        return build_rule_candidate(
            control,
            rule_id=self.rule_id,
            implementation_method=ImplementationMethod.SETTINGS_CATALOG,
            intune_area="Windows OS Hardening",
            setting_name="Security options",
            confidence=0.85,
            default_value="Enabled",
        )

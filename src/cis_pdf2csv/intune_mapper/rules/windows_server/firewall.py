from __future__ import annotations

from ...models import ImplementationMethod, MappingCandidate, NormalizedControl
from ..base import MappingRule, build_rule_candidate


class FirewallRule(MappingRule):
    rule_id = "windows_server_2025.firewall"

    def matches(self, control: NormalizedControl) -> bool:
        return "firewall" in control.title.lower()

    def apply(self, control: NormalizedControl) -> MappingCandidate:
        return build_rule_candidate(
            control,
            rule_id=self.rule_id,
            implementation_method=ImplementationMethod.ENDPOINT_SECURITY,
            intune_area="Firewall",
            setting_name="Microsoft Defender Firewall",
            confidence=0.82,
        )

from __future__ import annotations

from ...models import ImplementationMethod, MappingCandidate, NormalizedControl
from ..base import MappingRule, build_rule_candidate


class AuditPolicyRule(MappingRule):
    rule_id = "windows_server_2025.audit_policy"

    def matches(self, control: NormalizedControl) -> bool:
        return "audit" in control.title.lower()

    def apply(self, control: NormalizedControl) -> MappingCandidate:
        return build_rule_candidate(
            control,
            rule_id=self.rule_id,
            implementation_method=ImplementationMethod.SETTINGS_CATALOG,
            intune_area="Audit Policy",
            setting_name="Advanced Audit Policy Configuration",
            confidence=0.78,
        )

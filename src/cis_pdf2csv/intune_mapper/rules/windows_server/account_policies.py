from __future__ import annotations

from ...models import ImplementationMethod, MappingCandidate, NormalizedControl
from ..base import MappingRule, build_rule_candidate


class AccountPoliciesRule(MappingRule):
    rule_id = "windows_server_2025.account_policies"

    def matches(self, control: NormalizedControl) -> bool:
        t = control.title.lower()
        return "password" in t or "account lockout" in t

    def apply(self, control: NormalizedControl) -> MappingCandidate:
        return build_rule_candidate(
            control,
            rule_id=self.rule_id,
            implementation_method=ImplementationMethod.SETTINGS_CATALOG,
            intune_area="Account Policies",
            setting_name="Password and lockout policy",
            confidence=0.8,
        )

from __future__ import annotations

from ...models import ImplementationMethod, MappingCandidate, NormalizedControl
from ..base import MappingRule, build_rule_candidate


class EventLogRule(MappingRule):
    rule_id = "windows_server_2025.event_log"

    def matches(self, control: NormalizedControl) -> bool:
        t = control.title.lower()
        return "event log" in t or "log size" in t

    def apply(self, control: NormalizedControl) -> MappingCandidate:
        return build_rule_candidate(
            control,
            rule_id=self.rule_id,
            implementation_method=ImplementationMethod.SETTINGS_CATALOG,
            intune_area="Event Log",
            setting_name="Event log retention and size",
            confidence=0.75,
        )

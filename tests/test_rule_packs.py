import unittest

from cis_pdf2csv.intune_mapper.models import MappingInputControl
from cis_pdf2csv.intune_mapper.resolver import resolve_control, resolve_controls


def windows_control(**changes):
    values = {
        "benchmark_name": "CIS Microsoft Windows Server 2025 Benchmark",
        "benchmark_version": "1.0",
        "profile": "L1",
        "control_id": "1.1",
        "title": "(L1) Ensure Microsoft Defender Antivirus is Enabled",
        "recommendation": "Enabled",
    }
    values.update(changes)
    return MappingInputControl(**values)


class RulePackTests(unittest.TestCase):
    def test_defender_rule(self):
        control = windows_control()
        mapping, conflict = resolve_control(control)
        self.assertIsNone(conflict)
        self.assertEqual(mapping.rule_id, "windows_server_2025.defender")
        self.assertEqual(mapping.benchmark_family, "microsoft-windows-server")

    def test_manual_review_fallback(self):
        control = windows_control(
            control_id="9.9",
            title="Some niche control with no direct mapping",
            recommendation="Custom vendor setting",
        )
        mapping, _ = resolve_control(control)
        self.assertEqual(mapping.implementation_type, "manual_review")

    def test_m365_identical_title_does_not_receive_windows_mapping(self):
        control = windows_control(
            benchmark_name="CIS Microsoft 365 Foundations Benchmark",
            benchmark_family="microsoft-365-foundations",
        )
        mapping, conflict = resolve_control(control)
        self.assertIsNone(conflict)
        self.assertEqual(mapping.implementation_type, "manual_review")
        self.assertEqual(mapping.reason_code, "UNSUPPORTED_BENCHMARK_FAMILY")
        self.assertNotEqual(mapping.rule_id, "windows_server_2025.defender")

    def test_unknown_and_explicit_unsupported_families_are_not_windows(self):
        for control in (
            MappingInputControl(control_id="1", title="Ensure Microsoft Defender Antivirus is Enabled"),
            windows_control(benchmark_family="ambiguous"),
            windows_control(benchmark_family="invented-unsupported-family"),
        ):
            mapping, _ = resolve_control(control)
            self.assertEqual(mapping.implementation_type, "manual_review")
            self.assertEqual(mapping.reason_code, "UNSUPPORTED_BENCHMARK_FAMILY")

    def test_mixed_family_resolution_is_deterministic_and_only_maps_windows(self):
        windows = windows_control(control_id="2")
        cloud = windows_control(
            control_id="1",
            benchmark_name="CIS Microsoft 365 Foundations Benchmark",
            benchmark_family="microsoft-365-foundations",
        )
        forward = resolve_controls([windows, cloud])
        reverse = resolve_controls([cloud, windows])
        self.assertEqual(forward.model_dump(), reverse.model_dump())
        self.assertEqual(
            [mapping.benchmark_family for mapping in forward.mappings],
            ["microsoft-365-foundations", "microsoft-windows-server"],
        )
        self.assertEqual(forward.mappings[0].reason_code, "UNSUPPORTED_BENCHMARK_FAMILY")
        self.assertEqual(forward.mappings[1].rule_id, "windows_server_2025.defender")


if __name__ == "__main__":
    unittest.main()

import unittest

from cis_pdf2csv.intune_mapper.llm_fallback import suggest_manual_review_mappings
from cis_pdf2csv.intune_mapper.models import IntuneMapping


class MockClient:
    def suggest_mapping(self, mapping: IntuneMapping) -> dict:
        return {
            "suggested_implementation_type": "settings_catalog",
            "suggested_intune_area": "Mocked Area",
            "suggested_setting_name": "Mocked Setting",
            "suggested_value": "Enabled",
            "confidence": 0.9,
            "reasoning": "mock",
        }

    def suggest_mappings_batch(
        self,
        mappings: list[IntuneMapping],
    ) -> list[dict]:
        return [self.suggest_mapping(mapping) for mapping in mappings]


class LLMFallbackTests(unittest.TestCase):
    def test_only_manual_review_gets_suggestions(self) -> None:
        suggestions = suggest_manual_review_mappings(
            [
                IntuneMapping(
                    cis_id="1",
                    title="manual",
                    implementation_type="manual_review",
                    intune_area="Manual Review",
                    setting_name="Unmapped",
                    value="N/A",
                    confidence=0.0,
                    rule_id="fallback.manual_review",
                ),
                IntuneMapping(
                    cis_id="2",
                    title="mapped",
                    implementation_type="settings_catalog",
                    intune_area="x",
                    setting_name="y",
                    value="Enabled",
                    confidence=0.8,
                    rule_id="r",
                ),
            ],
            client=MockClient(),
        )
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0].cis_id, "1")


if __name__ == "__main__":
    unittest.main()

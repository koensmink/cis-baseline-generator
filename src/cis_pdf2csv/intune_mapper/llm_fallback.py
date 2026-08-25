from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Protocol

from .models import CandidateSource, IntuneMapping, MappingStatus, SuggestedMapping


class LLMClient(Protocol):
    def suggest_mapping(self, mapping: IntuneMapping) -> dict: ...
    def suggest_mappings_batch(self, mappings: list[IntuneMapping]) -> list[dict]: ...


class HeuristicLLMClient:
    def suggest_mapping(self, mapping: IntuneMapping) -> dict:
        return {
            "suggested_implementation_type": "settings_catalog",
            "suggested_intune_area": "Manual Triage",
            "suggested_setting_name": f"Review {mapping.title}",
            "suggested_catalog_identifier": None,
            "suggested_value": str(mapping.value) if mapping.value is not None else "",
            "confidence": 0.35,
            "reasoning": "Heuristic fallback generated because no external LLM client was provided.",
        }

    def suggest_mappings_batch(self, mappings: list[IntuneMapping]) -> list[dict]:
        return [self.suggest_mapping(m) for m in mappings]


class OpenAILLMClient:
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4.1-mini",
        cache_path: str | Path | None = None,
        batch_size: int = 5,
        max_retries: int = 2,
    ) -> None:
        from openai import OpenAI

        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.cache_path = Path(cache_path) if cache_path else None
        self._cache: dict[str, dict] = {}
        self.batch_size = batch_size
        self.max_retries = max_retries

        if self.cache_path:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            if self.cache_path.exists():
                try:
                    self._cache = json.loads(
                        self.cache_path.read_text(encoding="utf-8")
                    )
                except (OSError, json.JSONDecodeError):
                    self._cache = {}

    def _cache_key(self, mapping: IntuneMapping) -> str:
        raw = json.dumps(mapping.__dict__, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(raw.encode()).hexdigest()

    def _save_cache(self) -> None:
        if self.cache_path:
            self.cache_path.write_text(
                json.dumps(self._cache, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

    def _normalize_confidence(self, value) -> float:
        """
        Normalize LLM confidence values to a float between 0.0 and 1.0.
        Accepts floats, ints, numeric strings, and labels like high/medium/low.
        """
        if value is None:
            return 0.5

        if isinstance(value, (int, float)):
            v = float(value)
            return max(0.0, min(1.0, v))

        if isinstance(value, str):
            t = value.strip().lower()

            mapping = {
                "very high": 0.95,
                "high": 0.85,
                "medium": 0.60,
                "moderate": 0.60,
                "low": 0.35,
                "very low": 0.15,
            }

            if t in mapping:
                return mapping[t]

            try:
                v = float(t)
                return max(0.0, min(1.0, v))
            except ValueError:
                return 0.5

        return 0.5

    def _normalize_suggested_value(self, value, fallback_value) -> str:
        """
        Normalize suggested_value to a string because SuggestedMapping expects str.
        """
        if value is None:
            return str(fallback_value) if fallback_value is not None else ""

        if isinstance(value, bool):
            return "Enabled" if value else "Disabled"

        if isinstance(value, (int, float)):
            return str(value)

        if isinstance(value, str):
            return value.strip()

        return str(value)

    def suggest_mapping(self, mapping: IntuneMapping) -> dict:
        return self.suggest_mappings_batch([mapping])[0]

    def suggest_mappings_batch(self, mappings: list[IntuneMapping]) -> list[dict]:
        results: list[dict | None] = [None] * len(mappings)
        uncached: list[tuple[int, IntuneMapping]] = []

        for i, m in enumerate(mappings):
            key = self._cache_key(m)
            if key in self._cache:
                results[i] = self._cache[key]
            else:
                uncached.append((i, m))

        for i in range(0, len(uncached), self.batch_size):
            chunk = uncached[i : i + self.batch_size]
            indices = [x[0] for x in chunk]
            controls = [x[1] for x in chunk]

            generated = self._call_with_retry(controls)

            for idx, value in zip(indices, generated):
                key = self._cache_key(mappings[idx])
                self._cache[key] = value
                results[idx] = value

        self._save_cache()
        return [r for r in results if r is not None]

    def _call_with_retry(self, mappings: list[IntuneMapping]) -> list[dict]:
        for attempt in range(self.max_retries + 1):
            try:
                return self._call_openai_batch(mappings)
            except Exception as e:  # noqa: BLE001 - provider SDK errors are heterogeneous
                import traceback

                print(f"[LLM retry {attempt}] {type(e).__name__}: {e}")
                traceback.print_exc()
                time.sleep(1)

        return [self._fallback(m) for m in mappings]

    def _call_openai_batch(self, mappings: list[IntuneMapping]) -> list[dict]:
        system_prompt = (
            "Return ONLY valid JSON. No markdown, no explanation.\n"
            "Schema:\n"
            "{ 'suggestions': [ { cis_id, suggested_implementation_type, "
            "suggested_intune_area, suggested_setting_name, suggested_catalog_identifier, "
            "suggested_value, confidence, reasoning } ] }\n"
            "'confidence' must be a numeric value between 0.0 and 1.0. "
            "Do not use strings like High, Medium, or Low. "
            "'suggested_value' must always be a string."
        )

        payload = [
            {
                "cis_id": m.cis_id,
                "title": m.title,
                "value": str(m.value) if m.value is not None else "",
            }
            for m in mappings
        ]

        response = self.client.chat.completions.create(
            model=self.model,
            temperature=0,
            max_tokens=1500,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ],
        )

        raw = response.choices[0].message.content or "{}"

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            print("INVALID JSON FROM LLM:")
            print(raw)
            return [self._fallback(m) for m in mappings]

        suggestions = data.get("suggestions", [])

        result: list[dict] = []
        by_id = {m.cis_id: m for m in mappings}

        for item in suggestions:
            original = by_id.get(item.get("cis_id"))
            if not original:
                continue

            result.append(
                {
                    "suggested_implementation_type": item.get(
                        "suggested_implementation_type", "settings_catalog"
                    ),
                    "suggested_intune_area": item.get(
                        "suggested_intune_area", "Manual Triage"
                    ),
                    "suggested_setting_name": item.get(
                        "suggested_setting_name", f"Review {original.title}"
                    ),
                    "suggested_catalog_identifier": item.get(
                        "suggested_catalog_identifier"
                    ),
                    "suggested_value": self._normalize_suggested_value(
                        item.get("suggested_value", original.value),
                        original.value,
                    ),
                    "confidence": self._normalize_confidence(
                        item.get("confidence", 0.5)
                    ),
                    "reasoning": item.get("reasoning", "LLM generated"),
                }
            )

        if len(result) != len(mappings):
            print("WARNING: LLM returned incomplete batch")
            missing = len(mappings) - len(result)
            for _ in range(missing):
                result.append(self._fallback(mappings[len(result)]))

        return result

    def _fallback(self, m: IntuneMapping) -> dict:
        return {
            "suggested_implementation_type": "settings_catalog",
            "suggested_intune_area": "Manual Triage",
            "suggested_setting_name": f"Review {m.title}",
            "suggested_catalog_identifier": None,
            "suggested_value": self._normalize_suggested_value(m.value, m.value),
            "confidence": 0.35,
            "reasoning": "Fallback due to incomplete LLM response",
        }


def suggest_manual_review_mappings(
    mappings: list[IntuneMapping],
    client: LLMClient | None = None,
) -> list[SuggestedMapping]:
    llm = client or HeuristicLLMClient()

    manual_review = [
        m for m in mappings if m.mapping_status == MappingStatus.MANUAL_REVIEW
    ]
    if not manual_review:
        return []

    data = llm.suggest_mappings_batch(manual_review)

    source = (
        CandidateSource.HEURISTIC
        if isinstance(llm, HeuristicLLMClient)
        else CandidateSource.LLM
    )
    return [
        SuggestedMapping(
            cis_id=m.cis_id,
            title=m.title,
            candidate_source=source,
            **d,
        )
        for m, d in zip(manual_review, data)
    ]

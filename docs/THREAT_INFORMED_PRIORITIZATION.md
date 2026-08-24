# Threat-Informed Control Prioritization

## Purpose and compatibility boundary

Phase 3 adds a deterministic, advisory threat-relevance overlay. It answers which already-known source recommendations are especially relevant to resolved threat knowledge and why. It never changes the base Mandatory proposal.

The production Mandatory engine, Candidate Mandatory criteria, Review Required and Regular Control semantics, boundary completeness, benchmark-family adapters, shadow mode, parser, Intune mapping, CLI, CSV schemas, and Security Knowledge Catalog remain independent and unchanged. With no threat input, production behavior and output are identical.

No Phase 1, 2, or 3 code uses AI, live feeds, network access, keyword inference, or customer-vulnerability inference.

## Phase 3 architecture

```text
Base Mandatory Engine
        │
        └────────────── base_proposal
                         │
ThreatContext            │
      ↓                  │
ThreatResolution         │
      ↓                  │
Mitigation Projection    │
      ↓                  │
Threat Relevance Overlay ┘
      ↓
Advisory prioritization
```

Phase 3 is bounded by `projection.py` and `prioritization.py` inside `cis_pdf2csv.security_knowledge.threat_intelligence`. Production paths do not import or invoke these modules.

The only control join is the existing atomic `MitigationMapping`:

```text
ThreatResolution
  → resolved AttackPath and Boundary
  → active MitigationMapping
  → composite SourceIdentity
  → immutable base Mandatory assessment
  → advisory overlay
```

There is no direct ThreatContext-to-control mapping and no second control-to-boundary system. Title-only matches and controls without mappings cannot participate.

## Phase 2 resolution contract

Phase 2 resolves explicit catalog IDs using path, technique, and scenario precedence. It retains all valid paths, boundaries, outcomes, evidence lineage, conservative confidence, and deterministic ordering. It performs no free-text interpretation. Validity is `[valid_from, valid_until)` and historical mode is explicit. Deprecated and superseded references are never silently replaced.

The stable `threat_context_id` remains separate from its provenance `object_version`; Phase 3 uses both as a deterministic resolution driver identity.

## Control mitigation projection

`ThreatControlProjection` retains composite `SourceIdentity`, control ID/title, base proposal, mapping ID, context/resolution IDs, intersecting path/boundary/technique IDs, capability and enforced security effect, mitigation role and strength, boundary role, threat and control applicability, confidence, overlap metadata, eligibility, and structured findings.

A projection requires an existing mapping whose AttackPath occurs in a `ThreatResolution`. A missing resolved boundary is retained as an explicit review-capped projection, never guessed. Inactive mappings are ineligible. Below-High mapping confidence, conditional/unresolved applicability, or non-resolved knowledge status remains visible but is review-capped.

## Base proposal immutability

The overlay copies `base_proposal` verbatim from the scoped production assessment. It never writes a new `proposal`. Therefore:

- Candidate Mandatory remains Candidate Mandatory;
- Review Required remains Review Required; and
- Regular Control remains Regular Control, including when threat relevance is High.

Threat relevance is an advisory dimension, not a classifier cutover.

## Relevance and confidence

Threat relevance and priority confidence are independent. Relevance uses four non-numeric values:

- `Normal`: an intersecting mapped control is tuning, information-hiding, operational, inactive, or otherwise ineligible for escalation. Controls without any intersection are omitted from the optional overlay.
- `Elevated`: a valid intersection exists but is supporting/detection-oriented, conditional, below High confidence, partially resolved, boundary-incomplete, or review-capped.
- `High`: requires a fully resolved active knowledge chain, High conservative confidence, a resolved path and boundary, universal benchmark applicability, no participation blocker, a preventive/restrictive/isolating/protective mapping, and a primary, complementary-core, or prerequisite role.
- `Critical`: reserved for the High conditions plus a future structured immediate-exploitation/activity driver.

Phase 1 has no structured exploitation/activity state. Phase 3 therefore deliberately caps at High. Critical severity alone, prose, incident-like wording, or evidence type cannot produce Critical relevance.

Confidence reuses `High`, `Medium`, and `Low`. Per-driver confidence is the minimum of `ThreatResolution.confidence` and `MitigationMapping.confidence`; Phase 2 already guarantees resolution confidence cannot exceed ThreatContext confidence. No numeric or hidden weighted score exists.

## Advisory actions

Actions are separate from relevance:

- Normal → `none`;
- Elevated → `monitor`, or `review` when an explicit cap requires analyst judgment;
- High → `prioritize`;
- Critical → `urgent_prioritize` (currently unreachable).

Mandatory, Required, Failed, and Noncompliant are not overlay actions.

## Role-based ceilings

- Standalone primary, complementary-core, and prerequisite preventive effects may reach High.
- Supporting hardening is capped at Elevated.
- Detection, investigation, and recovery are capped at Elevated.
- Fine-tuning, information-hiding, and operational roles have a Normal ceiling.

These rules use generic model roles and contain no Windows-specific semantics. Detection controls may become visible, but generic logging is not included merely because a path exists; it still needs an authoritative mapping.

## Applicability

Threat applicability, source/control applicability, and customer deployment applicability remain distinct. Universal benchmark applicability may support High. `mandatory_when_deployed` and unresolved applicability are projected but capped at Elevated with `review`; the resolver never assumes that a customer's feature is deployed or that the environment is vulnerable.

## Multiple threats and paths

Every mapping/context pair becomes a separate `ThreatPriorityDriver` with its own path, boundary, effect, role, relevance, rationale, confidence, and caps. Aggregation preserves all drivers and selects the highest valid relevance without summing scores. An incomplete driver does not invalidate an independently complete driver. Distinct paths remain distinct assertions.

## Equivalence and overlap

Phase 3 reuses existing role, strength, overlap, related-control, security-effect, scope, and source-identity evidence. A broader primary mapping may reach High while an explicitly supporting narrower alternative remains Elevated. Multiple primary mappings claiming the same boundary, security effect, applicability, and resolution are ambiguous: each is capped at Elevated with `review`. Phase 3 never infers equivalence from titles.

## Explainability and deterministic output

Every non-Normal driver identifies the originating context and resolution, attack path, boundary, enforced security effect, mitigation/boundary role, base proposal, relevance reason, confidence, and every cap preventing a higher result. Text is concise and deterministic; no generated narrative is used.

Projection, drivers, overlays, findings, and summaries are frozen typed models. All inputs and output collections use canonical composite-identity/ID ordering. JSON uses sorted keys, compact separators, and no implicit timestamps.

## Summary

`ThreatPrioritySummary` reports projected controls, Normal/Elevated/High/Critical counts, review-capped controls, unique contexts/paths/boundaries, controls by immutable base proposal, and controls by mitigation role. It has no target percentages and does not modify production counts.

## Phase 3.1 CLI

`cis-threat-analyze` exposes the existing deterministic Phase 1–3 pipeline without duplicating its reasoning:

```bash
cis-threat-analyze \
  controls.jsonl \
  --threat-context threat-context.json \
  --at-time 2026-08-24T12:00:00Z \
  -o threat-overlay.csv
```

`controls.jsonl` contains parser-produced `ControlRecord` objects. Each repeated `--threat-context` argument names one structured JSON object that validates as `ThreatContext`; prose and URLs are not accepted. `--historical` explicitly enables Phase 2 historical resolution. `--at-time` accepts a timezone-aware ISO-8601 instant and makes lifecycle evaluation reproducible; when omitted, current UTC time is used.

The CLI recomputes base assessments internally through the unchanged `assess_controls()` Mandatory pipeline. It joins those assessments by composite `SourceIdentity`, adapts existing atomic mitigation mappings, uses catalog migration relationships where a legacy boundary-set ID needs its normative boundary, and then calls the existing resolver, projection, and prioritization APIs. It never joins on bare control ID.

For `-o threat-overlay.csv`, the deterministic artifacts are:

- `threat-overlay.csv`: all projected overlays;
- `threat-overlay-high.csv`: High and Critical only;
- `threat-overlay-review.csv`: only overlays whose advisory action is `review`;
- `threat-overlay.json`: complete structured overlay models; and
- `threat-overlay-summary.json`: priority summary, projection findings, and full ThreatResolution metadata.

The Rich summary reports supplied contexts, projected controls, each relevance level, and review-capped controls. All-inactive contexts succeed, remain visible in summary JSON resolution metadata, and produce an empty overlay. Missing contexts and malformed or blocking input exit with status 2 and concise diagnostics.

CSV columns have a fixed order and retain source scope, immutable base proposal, relevance/confidence/action, contexts and resolutions, paths, boundaries, techniques, all role dimensions, applicability, security effects, rationale, and findings. JSON keys and all model collections are deterministically ordered. No random identifier or output timestamp is added. Supplying the same inputs and `--at-time` produces byte-identical artifacts.

The CLI adds no AI, network access, remote ingestion, or classifier cutover. In particular, `base_proposal: Regular Control` remains unchanged when `threat_relevance: High` and `advisory_action: prioritize`.

## Phase 4A: AI interpretation contract and governance

Phase 4A implements the typed, provider-neutral contract boundary only:

```text
Unstructured threat advisory
        ↓
Untrusted source document
        ↓
AI interpretation contract
        ↓
ProposedThreatInterpretation
        ↓
Validation
        ↓
Human approval
        ↓
ThreatContext
        ↓
existing deterministic Phase 2/3 pipeline
```

AI is not authoritative. It cannot classify controls, assign Mandatory status,
assign threat relevance or advisory actions, select CIS controls, decide boundary
completeness, or infer customer vulnerability. Output is untrusted until both
deterministic validation and explicit human approval succeed. Validation alone does
not imply approval.

Source advisories are untrusted input. Material assertions retain evidence locators
and support types; active exploitation and affected technology require explicit
source evidence. Unknown or malformed catalog IDs, forbidden decision fields,
unsupported model knowledge, sensitive output, and attempted prompt-injection
output fail closed.

There is no provider integration, model call, network access, or remote ingestion
in Phase 4A. Activity state remains at the interpretation boundary and does not
change Phase 3 relevance rules. See
[AI Threat Interpretation Contract](AI_THREAT_INTERPRETATION_CONTRACT.md) for the
authority, grounding, provenance, adversarial-input, and conversion rules.

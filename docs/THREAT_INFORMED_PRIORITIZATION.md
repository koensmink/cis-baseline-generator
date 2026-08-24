# Threat-Informed Control Prioritization

## Purpose and phase boundary

Phase 2 adds deterministic resolution from a `ThreatContext` to existing, source-independent Security Knowledge Catalog concepts. It answers which existing security knowledge is relevant to an asserted threat context. It does not score, rank, promote, demote, or classify any CIS recommendation.

The production Mandatory engine, Candidate Mandatory criteria, Review Required and Regular Control semantics, boundary completeness, benchmark-family adapters, shadow mode, parser, Intune mapping, CLI, and Security Knowledge Catalog remain independent and unchanged. When no context is evaluated, application behavior is unchanged.

## Phase 2 architecture

```text
ThreatContext
     ↓
Deterministic Knowledge Resolver
     ├─ ThreatScenario
     ├─ AttackTechnique
     ├─ AttackPath
     ├─ SecurityBoundary
     └─ SecurityOutcome

Base Mandatory Engine (separate and unchanged)
```

The resolver is bounded within `cis_pdf2csv.security_knowledge.threat_intelligence`. Production classification paths do not import or invoke it. It builds deterministic inverse indexes in memory and never adds reverse threat-context identifiers to catalog objects.

## ThreatContext identity and revision

The stable `threat_context_id` identifies the context independently of its content. It is not a full-content hash. Resolution output separately retains the context provenance `object_version` as `threat_context_revision`. External advisories and evidence identifiers remain source/evidence references rather than context identity.

## Resolution statuses

- `resolved`: an active context has an unambiguous valid chain containing active threat scenario, technique, attack path, boundary, and outcome concepts.
- `partially_resolved`: at least one valid knowledge relationship is retained, but a non-ambiguous chain gap remains, such as an unattached technique or a path without a boundary or outcome.
- `review_required`: an inactive catalog reference or lifecycle successor choice needs human judgment. This is a knowledge-resolution status, not the Mandatory engine's Review Required classification.
- `unresolved`: no reliable knowledge relationship can be established, or an active-participation blocker prevents resolution.
- `inactive`: a valid context is not active at the explicitly supplied evaluation instant.

These statuses never classify controls.

## Explicit-reference precedence and traversal

Resolution uses only identifiers asserted by the context and authoritative catalog relationships:

1. Explicit active AttackPath references are resolved first. Their scenarios, techniques, boundaries, and outcomes are followed exactly as modeled.
2. Explicit active AttackTechnique references use a reconstructed `technique_id → AttackPath` index. Every active match is preserved.
3. Explicit active ThreatScenario references use a reconstructed `threat_scenario_id → AttackPath` index. Every active match is preserved.
4. Prose or evidence without catalog identifiers is not keyword-matched or semantically inferred; it remains unresolved in Phase 2.

Multiple valid matching paths are not ambiguous and are never arbitrarily collapsed. Missing links are not invented. Boundary resolution names relevant boundaries only; it does not evaluate CIS `BoundarySet` completeness. Outcome resolution retains technical `SecurityOutcome` objects only and does not infer business risk or create customer-specific risks.

## Evidence lineage and deterministic output

Each resolved reference records its object ID and type, relationship source, originating context ID, conservative confidence, and compact source/evidence identifiers. Full evidence blobs are not copied into every relationship.

Results use immutable Pydantic models, canonical ordering for all object collections, findings, and resolution paths, sorted JSON keys, compact separators, and no implicit timestamps. Equivalent contexts and catalogs therefore produce byte-stable JSON regardless of input identifier ordering. The catalog is never mutated.

## Confidence propagation

Resolution reuses the existing `High`, `Medium`, and `Low` values and introduces no numeric score. A relationship's confidence is the least-confident value among the originating context, its attack path where applicable, and catalog technique/scenario confidence where modeled. Aggregate resolution confidence is the least-confident resolved relationship. It can never exceed context confidence. Confidence does not rank controls.

## Active time and lifecycle behavior

Validity is the half-open interval `[valid_from, valid_until)`: `valid_from` is inclusive and `valid_until` is exclusive. Evaluation requires an explicit timezone-aware instant and never reads the system clock. Expired and future contexts are inactive in normal mode and do not produce active resolution. Invalid or timezone-incomplete temporal windows are unresolved participation blockers.

Historical mode is explicit in both the resolver call and output. It may retain deprecated or superseded objects for historical analysis. It does not silently rewrite catalog references.

## Successor handling

Normal resolution uses active catalog objects only. An explicit deprecated or superseded reference is preserved in a structured finding and sets `review_required`; it is not included as an active resolved object. Findings distinguish deprecated references, superseded references with one active successor suggestion, multiple active successor candidates, and no active successor. Candidate IDs and the original lifecycle reason are retained, but replacement always requires a later human decision.

## Applicability boundary

Resolution retains affected technology families, targeted asset classes, and threat applicability scope. These describe the threat assertion, not CIS recommendation applicability and not whether a customer's environment is affected. An unresolved applicability scope is a participation blocker when active resolution cannot safely determine scope; the resolver does not guess between knowledge branches.

## Coverage reporting

The deterministic aggregate report counts the five resolution statuses plus referenced techniques, resolved attack paths, boundaries, outcomes, and unresolved external/catalog references. It contains no CIS recommendation or control counts.

## Why no control priority exists yet

Phase 2 stops at reusable security knowledge. It does not project threat relevance onto mitigation mappings or controls, so it cannot change Mandatory classification or produce a priority overlay. Governance workflow and analyst-approval rules for control-priority participation are also outside this phase.

Phase 3 is future work and is not implemented:

```text
ThreatResolution
      ↓
Control/Boundary Mitigation Projection
      ↓
Threat-Informed Priority Overlay
```

Phase 3 must define projection semantics, conflict handling, applicability and approval rules, overlay representation, and regression safeguards before any control-level output is introduced. Phase 4 may later address unstructured interpretation and operational ingestion; Phase 2 uses no AI, live feeds, or network access.

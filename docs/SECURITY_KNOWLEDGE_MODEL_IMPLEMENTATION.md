# Security Knowledge Model Implementation

## Scope

This implementation adds the typed, deterministic domain layer defined by
`SECURITY_KNOWLEDGE_MODEL.md`. It does not add persistence, APIs, user
interfaces, AI, external-framework ingestion, or a new parser. The existing
Mandatory pipeline remains authoritative for Phase-1 classification.

## Implemented models

The package now provides:

- immutable validated identifier aliases for all normative ID families;
- `LifecycleStatus` and `Confidence`;
- typed `EvidenceItem` and the six evidence categories;
- source-extraction, catalog-object, mapping-evidence, review, and decision
  provenance;
- the active CAP-01 through CAP-10 `SecurityCapability` catalog;
- `BoundaryDefinition`, `BoundarySetDefinition`, and `BoundaryEvaluation`;
- `ThreatScenario` and an initial curated scenario for each current attack path;
- `AttackTechnique` and typed optional external mappings;
- reusable `AttackPath` catalog objects without source mapping IDs;
- separate `SecurityOutcome` and contextual `Risk` models;
- atomic `MitigationMapping` with separate boundary role, mitigation role, and
  mitigation strength;
- `CompensatingControlEvaluation`; and
- `MandatoryDecision` with explicit decision scope and human approval for
  Definitive Mandatory.

All new domain objects are frozen Pydantic models. Catalog identifiers are
validated without case or whitespace coercion.

## Deterministic validation

Structured `ValidationFinding` results contain a code, severity, object type and
ID, message, required action, and one of these effects:

- `invalid_object`;
- `mapping_rejected`;
- `review_required`; or
- `coverage_gap`.

Validators cover active catalog references, active ThreatScenario requirements,
attack-stage membership, scoped source identity, typed attributable evidence,
audit/reference-only activation, duplicate primary effects, boundary
completeness, compensation equivalence, the applicability/deployment matrix,
High-confidence Candidate chains, and lifecycle/historical evaluation rules.

Coverage uses the six normative states. A complete complementary core set is an
effective mitigation and is not reported as lacking primary protection. The old
`attack_paths_with_no_primary_mitigation` report key remains for compatibility
and is explicitly marked deprecated in report metadata.

## Compatibility behavior

`ControlAttackPathMapping` remains as a deprecated Phase-1 transport model so
existing Mandatory CSV output and tests continue to work. The explicit
`adapt_phase1_assessments` adapter creates atomic normative mappings without
mutating `ControlRecord` or `MandatoryAssessment` objects.

The adapter:

- constructs benchmark-scoped source recommendation identity;
- maps known Phase-1 boundary-set identities to explicit BoundaryDefinition IDs;
- translates the existing relationship into `boundary_role` without changing
  the original value;
- retains narrative evidence as typed source-control evidence;
- assigns deterministic mapping IDs from sorted control order; and
- returns findings and a Review Required recommendation when required normative
  information is missing.

The adapter does not feed its result back into the existing Mandatory pipeline,
so current classification results are not materially changed.

## Synthetic example

An invented authentication-integrity recommendation may produce one atomic
mapping:

```text
source: Invented framework|Invented benchmark|1.0|L1|1.1
capability: CAP-01
boundary: BND-IDENTITY-AUTHENTICATION
boundary set: BS-IDENTITY-AUTHENTICATION
threat scenario: TS-001
attack path: AP-001
stage: authentication
boundary role: boundary_set_core_member
mitigation role: prevent
strength: complementary
confidence: High
```

A second attack path or stage requires another mapping ID. Audit commands and
references may support traceability but cannot independently produce this
mapping.

## Known gaps

- The existing Mandatory runtime still exports the deprecated Phase-1 mapping
  shape for compatibility; normative atomic mappings are exported by advisory
  shadow mode.
- Catalog coverage is validated for the Windows reference and selected M365
  identity/application slices, not every benchmark domain.
- Medium and Low confidence meanings remain descriptive; they cannot satisfy a
  Candidate Mandatory decision.
- Formal condition-expression syntax and structured residual-path steps remain
  future model work. Unresolved conditions require review.
- No customer-specific Risk objects are created by generic benchmark analysis.

## Remaining path from advisory shadow

1. Continue producing current Mandatory outputs unchanged.
2. Run the implemented compatibility and family adapters and retain all
   structured findings.
3. Version catalog provenance and regenerate the deterministic publication
   artifact for every content change.
4. Compare shadow mappings and decisions against existing regression output.
5. Route missing, incomplete, or low-confidence knowledge to Review Required.
6. Adopt normative mappings as the canonical decision source only after decision
   parity and explicit review of every deviation.

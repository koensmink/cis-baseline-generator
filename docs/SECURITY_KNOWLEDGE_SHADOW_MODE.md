# Security Knowledge Mandatory Shadow Mode

## Purpose and status

Shadow mode measures a future catalog-based Mandatory decision pipeline against
the existing deterministic classifier. It is an explicitly enabled,
deterministic validation facility. Every normative decision is **advisory**. It
does not override, filter, promote, demote, or otherwise alter the production
proposal.

No persistence service, API, artificial intelligence, customer context, or
external knowledge ingestion is part of this phase. Definitive Mandatory
classification is also out of scope.

## Parallel pipelines

For each parser-produced control, the normal classifier runs unchanged and
produces the legacy proposal. The shadow pipeline then:

1. resolves a legacy boundary-set identity through the catalog compatibility
   migration;
2. creates deterministic atomic control/capability/boundary/threat/path
   mitigation mappings;
3. evaluates the applicable normative boundary-set definition;
4. validates catalog references and the evaluated knowledge chain;
5. derives an advisory proposal; and
6. compares it with the immutable legacy result.

A shadow Candidate requires active resolved knowledge, a primary,
complementary-core, or prerequisite mapping, a complete standalone or
complementary boundary, applicable benchmark scope, High confidence, and no
blocking or review-required validation finding. Missing mappings, incomplete
sets, unresolved applicability or overlap, insufficient confidence, and
validation findings produce Review Required. Supporting, fine-tuning,
operational, information-hiding, and detection-only effects remain Regular.

## Decision differences

Every comparison carries stable `SHADOW-*` codes. Codes distinguish an exact
proposal match, promotion, demotion, boundary identity migration, applicability
or confidence disagreement, missing mapping, incomplete boundary, and blocked
validation. A result can contain `SHADOW-MATCH` while also recording a boundary
identity difference because equality concerns the proposal, not every input to
the decision.

## Boundary evaluation

An evaluation records selected controls, required, satisfied, and missing
sub-boundaries, selected alternatives, completeness, residual attack path,
confidence, and deterministic evidence. A standalone primary mapping is
complete by itself. A complementary-core evaluation is effective only when its
required effects are complete; supporting mappings cannot fill a missing core
effect.

The current adapter preserves benchmark-specific Windows Server legacy set
membership while resolving it to generic catalog boundary and boundary-set
definitions. This is migration compatibility, not an assertion that a generic
catalog object contains CIS control identifiers.

## Cutover eligibility

`cutover_eligible` is reporting metadata only. It is true only when proposals
match, all references resolve, no blocking or review-required finding exists,
the required boundary is complete, and confidence is High. It never changes a
production decision. Deterministic ordering, stable identifiers, and byte-stable
exports are additional operational requirements.

## Outputs

With shadow mode enabled, the normal legacy files are written as before, plus:

- `mandatory-shadow-comparison.csv`;
- `mandatory-shadow-comparison.json`; and
- `mandatory-shadow-summary.json`.

The comparison files explicitly label normative results `advisory`. The summary
contains totals, exact matches, promotions, demotions, Review Required
differences, missing mappings, validation blocks, differences grouped by
boundary and attack path, proposal counts for both pipelines, and cutover
eligible control IDs.

## CLI usage

Shadow evaluation must be explicitly requested:

```bash
cis-mandatory-analyze controls.jsonl -o mandatory.csv --shadow-normative
```

Omitting `--shadow-normative` retains the existing behavior and produces no
shadow files.

## Known limitations

- Catalog migrations currently cover the existing Windows Server boundary sets;
  unmapped potentially qualifying controls deliberately remain Review Required,
  while deterministically supporting or operational effects remain Regular.
- Benchmark deployment state is not customer deployment context. Conditional
  applicability remains benchmark-scoped.
- Alternative and duplicate effects require explicit later adjudication.
- Shadow evidence reuses deterministic classifier evidence and compatibility
  migrations; it does not ingest new source material.
- Cutover metrics are evidence for a later phase, not authorization to cut over.

## Future cutover acceptance criteria

A future production cutover requires an explicit separately reviewed change,
zero blocking catalog validation findings, complete catalog coverage for the
supported benchmark scope, stable regression counts, deterministic exports,
reviewed resolution of alternative and duplicate effects, High-confidence
complete boundary evaluations, and documented human governance. Until all
criteria are accepted, the legacy classifier remains authoritative.

# Mandatory Control Engine — Phase 1

The Mandatory Control Engine is a deterministic preselection step over existing
`ControlRecord` JSONL output. It does not parse PDFs and does not alter the CIS
score.

## Integrated completion rule

A baseline meets the integrated rule when at least 85% of all in-scope CIS
recommendations are compliant **and** every control approved by an analyst as
Definitive Mandatory is compliant. Mandatory controls remain in the same CIS
denominator and do not receive a separate coverage percentage. Consequently, an
approved Mandatory control may not be placed in the maximum 15% non-compliant
portion.

## Proposals and human authority

Phase 1 emits only `Regular Control`, `Review Required`, and `Candidate
Mandatory`. Candidate Mandatory is a deterministic shortlist, not a final policy
designation. The engine never emits Definitive Mandatory; that designation
requires human review and approval.

Candidate Mandatory requires complete formal eligibility, at least one explicit
criterion, no blocking exclusion, sufficient evidence, a concrete
non-compensable reason, and High confidence. L1, Automated, implementation effort,
family membership, or title resemblance is never sufficient by itself.

## Criteria and exclusions

Stable `MC-CRIT-*` codes cover direct controls for legacy mechanisms,
authentication, privilege and credential protection, elevation, remote access,
execution, network boundaries and firewalls, transport protection, signing,
encryption, isolation, application control, essential audit/logging, and malware
protection.

Stable `EXCL-*` reasons block automatic candidacy for additive defense-in-depth,
user-experience or information-hiding effects, fine-tuning, implementation
dependence, reasonable compensation, insufficient evidence, ambiguous
applicability, and non-primary or overlapping relationships. Insufficient or
ambiguous evidence produces Review Required.

## Related-control comparison

Controls are compared within benchmark identity and profile using hierarchical
CIS IDs, shared security subject, title similarity, applicability, and
deterministic primary/supporting signals. Results distinguish primary boundary,
supporting, fine-tuning, detection-only, duplicate/overlapping, and independent
controls. Row position is never used as identity. Family classification supplies
organization only and cannot cause candidacy.

## Phase 1 limitations and Phase 2

Phase 1 uses explicit text patterns and cannot reliably resolve implicit
prerequisites, product-specific equivalence, all compensating architectures, or
subtle benchmark language. Such uncertainty is routed to Review Required. Phase
2 is planned to add an AI analyst proposal and a separate independent reviewer;
neither may replace deterministic evidence or human approval.

## CLI

```bash
cis-mandatory-analyze controls.jsonl -o mandatory-review.csv
```

This prints a production classification summary and writes the full assessment
CSV plus two direct review queues:

- `mandatory-review.csv` (all assessments)
- `mandatory-review-candidate-mandatory.csv` (Candidate Mandatory only)
- `mandatory-review-review-required.csv` (Review Required only)

All three CSVs carry the same human-reviewable source, criterion, boundary,
attack-path, rationale, confidence, and finding columns where those values are
available. `mandatory-review-summary.json` and attack-path coverage output are
also retained.

Use advisory normative comparison explicitly:

```bash
cis-mandatory-analyze controls.jsonl -o mandatory-review.csv --shadow-normative
```

Its stem-isolated `mandatory-review-shadow-*` files are advisory and do not
change or replace production classifications, counts, or review queues.

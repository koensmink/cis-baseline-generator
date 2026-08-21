# Threat-Informed Control Prioritization

## Purpose and Phase 1 boundary

Phase 1 introduces a normative, source-independent `ThreatContext` domain model and deterministic validation. It records concise, time-sensitive threat assertions and points to reusable Security Knowledge Catalog objects. It does not score controls, join threats to controls, promote controls, ingest feeds, or use AI.

Phase 1 cannot change a Mandatory decision. The production Mandatory engine, Candidate Mandatory criteria, Review Required and Regular Control semantics, boundary completeness, adapters, shadow mode, parser, Intune mapping, and CLI remain independent and unchanged.

## Architecture

```text
Threat intelligence
        ↓
ThreatContext
        ↓
[future] Knowledge resolution
        ↓
[future] Threat priority overlay

Base Mandatory Engine remains independent.
```

The bounded module is `cis_pdf2csv.security_knowledge.threat_intelligence`. It is not imported by production classification paths. Contexts point toward catalog techniques, attack paths, and threat scenarios; catalog objects never receive reverse context identifiers and remain source-independent.

## ThreatContext model

`ThreatContext` is frozen and uses immutable tuples. Its deterministic `THRCTX-...` identifier is internal; CVEs, government identifiers, Microsoft identifiers, and vendor advisory identifiers belong in `source_reference` or evidence `external_reference` fields.

The model records title and description, source identity/type, observed and publication times, validity window, assertion confidence, technical severity, lifecycle status, optional catalog relationship IDs, generic asset and technology families, applicability, concise evidence, and provenance. Relationship chains may be incomplete. A context can therefore describe a technique before an attack path is known, an attack path supported by scenarios, or an unresolved advisory retained for review.

Applicability is threat applicability, not CIS recommendation applicability. Its dimensions are global, technology family, product family, deployment-specific, sector-specific, environment-specific, and unresolved. For example, a context can apply to “Microsoft 365 cloud authentication” without asserting that a particular tenant is vulnerable. No customer-specific model is introduced.

## Confidence and severity

Threat confidence reuses the Security Knowledge `High`, `Medium`, and `Low` confidence model and describes confidence in the threat assertion. It never describes confidence in a Mandatory decision.

Technical severity is a separate deterministic `Low`, `Medium`, `High`, or `Critical` enum. Confidence, technical severity, active exploitation, and any future control priority remain distinct. A high-confidence, medium-severity context and a medium-confidence, critical-severity context are both valid. Phase 1 has no priority enum or scoring.

## Time validity and lifecycle

All supplied observation, publication, retrieval, and validity timestamps require explicit timezone information. `valid_from` cannot follow `valid_until`. `is_active(at_time)` requires an explicit timezone-aware timestamp and never consults the system clock. Future contexts are inactive until their validity starts. Expired contexts remain readable but are inactive; they produce an informational lifecycle finding. An `active` lifecycle status that contradicts a future or expired window is a blocking error.

Historical catalog resolution is opt-in. Deprecated or superseded catalog references block ordinary validation but become informational findings in historical mode.

## Evidence and provenance

Threat evidence supports vendor advisories, government advisories, vulnerability records, threat-research reports, incident observations, internal security observations, and analyst assertions. Each item keeps a source, external reference, concise assertion, confidence, available publication/retrieval times, and collection provenance. The model is intended for assertions and locators—not copied reports or copyrighted article text. Context provenance records authority, creation method, model/object versions, and optional creation/supersession metadata. No volatile timestamp is generated automatically.

## Validation and serialization

Validation findings are stable structured objects with error, warning, or informational severity and a `blocking` property. Errors cover invalid identifiers/time ranges, timezone omissions, lifecycle contradictions, and inactive catalog references. Warnings retain unresolved references, missing evidence, and unresolved applicability for review. Expired/future state is informational when lifecycle is consistent.

Catalog reference validation verifies techniques, attack paths, and threat scenarios without requiring all relationship types. Active objects are required unless historical mode is explicit. Deterministic JSON uses sorted keys, compact separators, stable set-like field/evidence ordering, and no random identifiers or implicit timestamps.

## Planned phases

- Phase 2: deterministic knowledge resolution from contexts to existing catalog concepts, without Mandatory cutover.
- Phase 3: a separately governed threat-priority overlay with explicit semantics and regression comparison.
- Phase 4: operational ingestion and lifecycle governance after provenance, legal, freshness, and review decisions are approved.

Before Phase 2, governance should decide successor-resolution rules, duplicate-context identity/revision policy, exact active-window boundary inclusivity, and which unresolved findings prevent use by a future overlay.

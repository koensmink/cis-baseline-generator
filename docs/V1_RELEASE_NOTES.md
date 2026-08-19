# v1 Release Candidate Notes

Package version: `1.0.0rc1`
Security Knowledge Catalog version: `1.2.0`

## Scope

The v1 release candidate includes structured CIS PDF parsing, benchmark-family
identity detection, deterministic family adapters, the Mandatory Control
Engine, the Security Knowledge Model and Catalog, attack-path and boundary
enrichment, advisory normative shadow evaluation, and downstream Windows Server
Intune mapping.

Validated reference scopes are Windows Server 2025 L1 and the selected Microsoft
365 identity/authentication, application registration and consent,
service-principal authorization, and workload-identity trust slices. Windows
Server production classification remains 27 Candidate Mandatory, 5 Review
Required, and 275 Regular Control.

## Advisory and unsupported behavior

Normative shadow results are advisory and never replace production Mandatory
classification. Incomplete knowledge remains Review Required. Microsoft 365
Intune mapping is unsupported and produces explicit manual-review output;
Windows rules are not evaluated for Microsoft 365 or unknown, ambiguous, or
unsupported families.

There is no classifier cutover, authoritative AI decision path, persistence,
database, API, UI, graph database, mail/DLP/sharing knowledge, or CWE/CVE
ingestion in v1. Optional OpenAI-backed Intune suggestions apply only to
already-manual-review mappings and remain non-authoritative.

## Distribution and validation

The runtime catalog is built from packaged Python definitions. The root
`security-knowledge-catalog.json` is a deterministic publication artifact, not
a runtime package-data dependency. Repository documentation is published with
the source distribution and is not required by the installed runtime.

A release candidate must pass the full pytest suite, scoped Ruff and mypy
checks, `git diff --check`, deterministic catalog regeneration, Windows
27/5/275 regression validation, M365 shadow regression validation, tracked
artifact checks, and an isolated wheel installation smoke test before promotion
to final `1.0.0`.

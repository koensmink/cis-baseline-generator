# CLI Usage

This document contains the operational command reference for the CIS Security Analysis and Baseline Engineering Toolkit.

The package currently installs eight console commands:

| Command | Purpose |
|---|---|
| `cis-pdf2csv` | Parse CIS Benchmark PDFs or dispatch a single JSONL input to the Intune mapper |
| `cis-mandatory-analyze` | Run deterministic Mandatory-control analysis and attack-path coverage |
| `cis-intune-map` | Map parser-produced JSONL to supported Intune artifacts |
| `cis-baseline-plan` | Enrich controls and create deterministic implementation waves |
| `cis-environment-scan` | Inventory declared Intune or GPO configuration for gap analysis |
| `cis-threat-analyze` | Resolve approved threat contexts and produce a deterministic advisory control-priority overlay |
| `cis-threat-interpret` | Use the optional OpenAI adapter to create an untrusted structured proposal from a local advisory |
| `cis-threat-approve` | Record explicit human review and optionally convert an approved proposal to a `ThreatContext` |

Benchmark diff is available through `python -m cis_pdf2csv.diff`.

There is currently no standalone Security Knowledge or catalog CLI.

## Installation

```bash
git clone https://github.com/koensmink/cis-baseline-generator.git
cd cis-baseline-generator
python -m pip install -e .
```

Python **3.10 or later** is required.

## CIS Benchmark Parsing

For parser behavior, supported identities, evidence fields, and limitations, see [CIS Benchmark Parser](CIS_BENCHMARK_PARSER.md).

### Parse to JSONL

```bash
cis-pdf2csv benchmark.pdf -p L1 -o controls.jsonl --format jsonl
```

Equivalent module invocation:

```bash
python -m cis_pdf2csv benchmark.pdf -p L1 -o controls.jsonl --format jsonl
```

### Parse to CSV

```bash
cis-pdf2csv benchmark.pdf -p L1 -o controls.csv --format csv
```

CSV output uses quoted UTF-8 with BOM for Excel compatibility.

### Parse without a profile filter

```bash
cis-pdf2csv benchmark.pdf -o controls.jsonl --format jsonl
```

When `-p/--profile` is omitted, all parser-recognized profiles are included.

### Parse multiple benchmark PDFs

```bash
cis-pdf2csv benchmark_v1.pdf benchmark_v2.pdf \
  -p L1 \
  -o combined.jsonl \
  --format jsonl
```

All positional inputs must be PDFs in parser mode. Records are emitted in deterministic order by benchmark name, benchmark version, and control ID.

## Mandatory Analysis

### Basic usage

```bash
cis-mandatory-analyze controls.jsonl -o mandatory-review.csv
```

Equivalent module invocation:

```bash
python -m cis_pdf2csv.mandatory.cli \
  controls.jsonl \
  -o mandatory-review.csv
```

### Output artifacts

For an output path such as `mandatory-review.csv`, the command writes:

```text
mandatory-review.csv
mandatory-review-candidate-mandatory.csv
mandatory-review-review-required.csv
mandatory-review-summary.json
mandatory-review-attack-path-coverage.json
```

The engine consumes parser-produced `ControlRecord` JSONL and does not modify the source file.

### Normative shadow evaluation

```bash
cis-mandatory-analyze \
  controls.jsonl \
  -o mandatory-review.csv \
  --shadow-normative
```

Shadow evaluation runs advisory catalog-based reasoning in parallel with the production classifier. It does not override production classifications or authorize classifier cutover.

See:

- [Mandatory Control Engine — Phase 1](mandatory-control-phase1.md)
- [Security Knowledge Model](SECURITY_KNOWLEDGE_MODEL.md)
- [Security Knowledge Catalog](SECURITY_KNOWLEDGE_CATALOG.md)

## Baseline Implementation Planning

The baseline planner consumes parser-produced `ControlRecord` JSONL. It does not
accept the CSV export because planning depends on typed parser fields and source
identity metadata.

### Create a baseline plan

```bash
cis-baseline-plan controls.jsonl -o implementation-plan
```

The default maximum execution-phase size is 75 controls.

### Complete workflow from PDF to implementation plan

```bash
cis-pdf2csv benchmark.pdf \
  --format jsonl \
  -o controls.jsonl

cis-baseline-plan controls.jsonl \
  -o implementation-plan \
  --max-phase-size 75
```

### Create smaller execution phases

```bash
cis-baseline-plan controls.jsonl \
  -o implementation-plan-small-phases \
  --max-phase-size 40
```

`--max-phase-size` must be at least 1. A work package larger than this limit is
split into separately named parts. Separate work packages are not mixed merely
to fill a phase.

Equivalent module invocation:

```bash
python -m cis_pdf2csv.baseline_planner.cli \
  controls.jsonl \
  -o implementation-plan \
  --max-phase-size 75
```

Show all available options:

```bash
cis-baseline-plan --help
```

The planner reuses the existing Mandatory classifier and Intune verification
boundary. It adds deterministic risk statements, prevented outcomes, security
categories, work packages, implementation impact, dependencies, priority, and an
explainable recommended wave. Unsupported or unverified Intune mappings remain
`needs_validation` and are never marked deployment-ready.

### Wave model

| Wave | Planning intent |
|---|---|
| 0 | Scope, prerequisites, conflicts, recovery, monitoring, and pilot preparation |
| 1 | Low-impact logging and visibility controls used to observe later changes |
| 2 | Foundational baseline controls with manageable implementation impact |
| 3 | Identity, privileged access, remote access, and network hardening |
| 4 | Controls requiring explicit compatibility testing and approved rollback |
| 5 | Manual implementation or Level 2 hardening after the core baseline |

The wave is a planning recommendation. The execution phase is the deployable
slice within that wave, such as `2A` or `2F`. Every execution phase contains one
work package. Operational impact, user impact, and rollback complexity are
recorded separately.

### Output artifacts

The output directory contains:

```text
implementation-plan/
├── enriched-controls.csv
├── enriched-controls.jsonl
├── implementation-phases.csv
├── manual-review.csv
├── phase-1.csv
├── phase-2A.csv ...
├── plan-summary.json
├── wave-00-prerequisites.csv
├── wave-01.csv ... wave-05.csv
├── waves.csv
└── work-packages.csv
```

| Artifact | Contents |
|---|---|
| `enriched-controls.csv` | All controls with risk, category, impact, priority, dependencies, readiness, wave, and phase |
| `enriched-controls.jsonl` | The same enriched records in structured JSONL |
| `work-packages.csv` | Stable functional groupings and the phases in which they occur |
| `implementation-phases.csv` | Phase names, counts, contained work package, dependencies, and control IDs |
| `waves.csv` | Complete control-level planning view across all waves |
| `wave-NN.csv` | All controls assigned to a numerical wave |
| `phase-*.csv` | Controls for one bounded, single-work-package execution phase |
| `wave-00-prerequisites.csv` | Nine checks to complete before implementation starts |
| `manual-review.csv` | Controls that are not verified as deployment-ready |
| `plan-summary.json` | Counts by wave, phase, priority, readiness, and work package |

Wave placement accounts for security priority, profile, implementation impact,
and explicit prerequisites. Work packages remain stable across phases. The plan
includes manual-assessment requirements and deployment readiness, but it is not
authorization to deploy a control.

## Environment Scan

### Live Intune inventory

```bash
export MS_GRAPH_ACCESS_TOKEN="<access-token>"

cis-environment-scan \
  --source intune \
  --tenant-id "<tenant-id>" \
  -o current-state.json
```

The token is read from `MS_GRAPH_ACCESS_TOKEN` by default and is never written to
the snapshot. Use `--access-token-env NAME` to select a different environment
variable. A live scan requests Settings Catalog policies and settings, legacy
device configurations, imported Group Policy configurations, assignments,
exclusions, and managed-device inventory.

If an individual Graph collection cannot be read, the snapshot is emitted as
`partial` with explicit `collection_errors`; unavailable data is not silently
treated as empty compliance evidence. The command returns a non-zero status for
a partial collection so unattended workflows cannot mistake it for a complete scan.

### Offline Intune Graph bundle

```bash
cis-environment-scan \
  --source intune \
  --input intune-export.json \
  -o current-state.json
```

The JSON object can contain `configurationPolicies`, `deviceConfigurations`,
`groupPolicyConfigurations`, and `managedDevices` as arrays or Graph collection
objects with a `value` array. Expanded `settings` and `assignments` are accepted;
live-collector fields `_settings` and `_assignments` are also supported.

### GPO report inventory

Export one or all GPO reports as XML on a domain-management workstation, then
transfer the report through the organisation's approved process:

```powershell
Get-GPOReport -All -ReportType Xml -Path .\all-gpos.xml
```

Scan one combined report, one individual report, or a directory of reports:

```bash
cis-environment-scan --source gpo --input all-gpos.xml -o current-state.json
cis-environment-scan --source gpo --input gpo-reports/ -o current-state.json
```

### Snapshot trust boundary

`current-state.json` distinguishes declared configuration and device inventory
from effective device state. Duplicate setting identities with different values
are reported as `potential_conflicts`; assignment overlap and resultant policy
must still be validated. Missing evidence is `not_observed`, never automatically
`non_compliant`.

See [Environment Scan](ENVIRONMENT_SCAN.md) for the schema, permissions, source
coverage, limitations, and downstream contract.

## Benchmark Diff

The diff module compares two parser-produced JSONL exports.

### Basic CSV diff

```bash
python -m cis_pdf2csv.diff \
  old.jsonl \
  new.jsonl \
  -o changes.csv
```

### JSONL diff

```bash
python -m cis_pdf2csv.diff \
  old.jsonl \
  new.jsonl \
  -o changes.jsonl \
  --format jsonl
```

If `--format` is omitted, the output extension determines whether CSV or JSONL is written.

### Diff with reports

```bash
python -m cis_pdf2csv.diff \
  old.jsonl \
  new.jsonl \
  -o changes.csv \
  --report report.md \
  --full-report report_full.md
```

The comparison reports:

- added controls;
- removed controls; and
- field-level changes.

The full report includes old and new field values for changed controls.

### Compare two benchmark versions

```bash
cis-pdf2csv benchmark_v1.pdf -p L1 -o v1.jsonl --format jsonl
cis-pdf2csv benchmark_v2.pdf -p L1 -o v2.jsonl --format jsonl

python -m cis_pdf2csv.diff \
  v1.jsonl \
  v2.jsonl \
  -o changes.csv \
  --report report.md \
  --full-report report_full.md
```

## Intune Mapping

### Basic usage

```bash
cis-intune-map controls.jsonl -o intune_out
```

Equivalent module invocation:

```bash
python -m cis_pdf2csv.intune_mapper.cli \
  controls.jsonl \
  -o intune_out
```

A single JSONL input can also be dispatched through the top-level command:

```bash
cis-pdf2csv controls.jsonl -o intune_out
```

### Output artifacts

```text
intune_out/
├── baseline.csv
├── manual_review.csv
├── conflicts.csv
├── intune_policies.json
└── suggested_mappings.jsonl
```

Current deterministic rules target supported Windows Server controls. A rule match
creates a candidate, not automatically a verified mapping. The authoritative
catalog resolver compares exact identifiers, implementation methods, platforms,
values, and catalog provenance. The CLI summary reports `Verified`, `Unverified`,
and `Manual review` separately.

`baseline.csv` and `intune_policies.json` contain only verified mappings.
`manual_review.csv` contains unverified candidates and explicit manual-review
fallbacks. CSV and JSON fields keep candidate source/confidence separate from
mapping status, verification source, match method, catalog version, and reason
codes.

The current `repository_local_authoritative_catalog` is a deliberately limited
local catalog (`local-test-v1`), not a claim of complete or current Microsoft
metadata. A future Microsoft Graph metadata loader can implement the typed catalog
interface without changing verification rules.

## Optional Intune LLM Fallback

LLM assistance applies only to controls unresolved after deterministic mapping.
Suggestions are defensively normalized, converted to typed candidates, and passed
through the same authoritative verifier. An LLM candidate always remains
unverified, even with confidence `1.0` and an exact catalog identifier. Confidence
is proposal metadata, never verification authority.

### Using an OpenAI API key

```bash
OPENAI_API_KEY=your_api_key \
cis-intune-map controls.jsonl -o intune_out --llm-fallback
```

### Override the model

```bash
OPENAI_API_KEY=your_api_key \
OPENAI_MODEL=gpt-4.1-mini \
cis-intune-map controls.jsonl -o intune_out --llm-fallback
```

If `--llm-fallback` is specified without `OPENAI_API_KEY`, the current implementation falls back to heuristic suggestions rather than making an OpenAI API call.

## Threat Intelligence

These commands form separate trust stages. `cis-threat-interpret` cannot create a
control overlay, `cis-threat-approve` performs no provider call, and only an
approved `ThreatContext` can enter `cis-threat-analyze`. For the model and authority
boundaries, see [Threat-Informed Control Prioritization](THREAT_INFORMED_PRIORITIZATION.md)
and [AI Threat Interpretation Contract](AI_THREAT_INTERPRETATION_CONTRACT.md).

### Analyze approved threat contexts

```bash
cis-threat-analyze \
  controls.jsonl \
  --threat-context threat-context.json \
  --at-time 2026-08-24T12:00:00Z \
  -o threat-overlay.csv
```

Repeat `--threat-context` to supply multiple structured contexts. The input must be
parser-produced `ControlRecord` JSONL; prose, URLs, and proposed interpretations are
not accepted. `--at-time` must include a timezone offset and makes lifecycle
evaluation reproducible. `--historical` explicitly allows historical catalog
resolution.

For `-o threat-overlay.csv`, the command writes:

```text
threat-overlay.csv
threat-overlay-high.csv
threat-overlay-review.csv
threat-overlay.json
threat-overlay-summary.json
```

The CSV contains projected overlays, while the structured JSON and summary retain
the causal drivers, exact context and resolution identities, projection findings,
provenance, and resolved knowledge metadata. The base Mandatory proposal is copied
unchanged.

Equivalent module invocation:

```bash
python -m cis_pdf2csv.security_knowledge.threat_intelligence.cli \
  controls.jsonl \
  --threat-context threat-context.json \
  --at-time 2026-08-24T12:00:00Z \
  -o threat-overlay.csv
```

### Interpret a local advisory with the optional provider

```bash
OPENAI_API_KEY="<runtime-secret>" cis-threat-interpret advisory.txt \
  --source-type vendor_advisory \
  --source-name "Example Vendor" \
  --source-reference "ADV-2026-001" \
  --model "<structured-output-capable-model>" \
  --generated-at 2026-08-24T12:00:00Z \
  -o proposed-threat.json
```

The command accepts a local UTF-8 text file, not a URL or live feed. It writes the
untrusted proposal artifact and `proposed-threat-summary.json`. Optional controls
are `--published-at`, `--timeout-seconds`, `--max-retries`, and
`--max-output-tokens`; `--provider` currently accepts only `openai`.

`OPENAI_API_KEY` is read at runtime. Provider output is validated fail-closed and
does not become a `ThreatContext` automatically.

### Inspect and approve a proposal

List all assertions without recording a decision:

```bash
cis-threat-approve proposed-threat.json --list-assertions
```

Record an approval after explicitly deciding every material assertion:

```bash
cis-threat-approve proposed-threat.json \
  --reviewer "security-engineer" \
  --approval approved \
  --reviewed-at 2026-08-24T12:30:00Z \
  --accept A-SOURCE \
  --accept A-PATH \
  --reject A-UNCERTAIN \
  --rationale "Reviewed against the locally supplied advisory" \
  -o threat-context.json
```

There is no implicit approval or accept-all option. Repeat `--accept` and `--reject`
as needed. Narrow, recorded corrections are available through `--set-confidence`,
`--set-severity`, `--set-valid-from`, `--set-valid-until`, and
`--set-applicability-scope`.

An `approved` decision writes:

```text
threat-context.json
threat-context-approval.json
threat-context-approval-summary.json
```

`rejected` and `needs_revision` are successful review outcomes but write only the
approval and summary artifacts; they do not create `threat-context.json`.

## Containers

### Build

Docker:

```bash
docker build -t cis-pdf2csv .
```

Podman:

```bash
podman build -t cis-pdf2csv .
```

The image entry point is the parser command.

### Parse a benchmark

Docker:

```bash
docker run --rm \
  -v "$PWD:/work" \
  -w /work \
  cis-pdf2csv \
  benchmark.pdf -p L1 -o controls.jsonl --format jsonl
```

Podman:

```bash
podman run --rm \
  -v "$PWD:/work:Z" \
  -w /work \
  cis-pdf2csv \
  benchmark.pdf -p L1 -o controls.jsonl --format jsonl
```

### Run Mandatory analysis

Docker:

```bash
docker run --rm \
  -v "$PWD:/work" \
  -w /work \
  --entrypoint python \
  cis-pdf2csv \
  -m cis_pdf2csv.mandatory.cli \
  controls.jsonl \
  -o mandatory-review.csv
```

Podman uses the same command with `-v "$PWD:/work:Z"` where SELinux relabeling is required.

### Run the Intune mapper

```bash
docker run --rm \
  -v "$PWD:/work" \
  -w /work \
  --entrypoint python \
  cis-pdf2csv \
  -m cis_pdf2csv.intune_mapper.cli \
  controls.jsonl \
  -o intune_out
```

### Intune mapper with LLM fallback

```bash
docker run --rm \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -v "$PWD:/work" \
  -w /work \
  --entrypoint python \
  cis-pdf2csv \
  -m cis_pdf2csv.intune_mapper.cli \
  controls.jsonl \
  -o intune_out \
  --llm-fallback
```

### Benchmark diff in a container

```bash
docker run --rm \
  -v "$PWD:/work" \
  -w /work \
  --entrypoint python \
  cis-pdf2csv \
  -m cis_pdf2csv.diff \
  v1.jsonl \
  v2.jsonl \
  -o changes.csv \
  --report report.md \
  --full-report report_full.md
```

> `:Z` is appropriate for Podman bind mounts on SELinux-enabled hosts. It is not required for ordinary Docker Desktop bind mounts.

## Command Source

Registered console entry points are defined in [`pyproject.toml`](../pyproject.toml).

Implementation:

- parser CLI: [`src/cis_pdf2csv/cli.py`](../src/cis_pdf2csv/cli.py)
- Mandatory CLI: [`src/cis_pdf2csv/mandatory/cli.py`](../src/cis_pdf2csv/mandatory/cli.py)
- Intune CLI: [`src/cis_pdf2csv/intune_mapper/cli.py`](../src/cis_pdf2csv/intune_mapper/cli.py)
- baseline planner CLI: [`src/cis_pdf2csv/baseline_planner/cli.py`](../src/cis_pdf2csv/baseline_planner/cli.py)
- threat analysis CLI: [`src/cis_pdf2csv/security_knowledge/threat_intelligence/cli.py`](../src/cis_pdf2csv/security_knowledge/threat_intelligence/cli.py)
- threat interpretation CLI: [`src/cis_pdf2csv/security_knowledge/threat_intelligence/ai/provider_cli.py`](../src/cis_pdf2csv/security_knowledge/threat_intelligence/ai/provider_cli.py)
- threat approval CLI: [`src/cis_pdf2csv/security_knowledge/threat_intelligence/ai/approval_cli.py`](../src/cis_pdf2csv/security_knowledge/threat_intelligence/ai/approval_cli.py)
- benchmark diff: [`src/cis_pdf2csv/diff.py`](../src/cis_pdf2csv/diff.py)

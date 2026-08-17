# CIS Security Analysis and Baseline Engineering Toolkit

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

This repository implements a CIS security-analysis and baseline-engineering toolkit with three primary layers:

1. **CIS benchmark parsing** into evidence-bearing structured records;
2. **Mandatory-control reasoning** over minimum-effective security boundaries; and
3. **Security Knowledge enrichment** through reusable capabilities, boundaries, threats, techniques, attack paths, and outcomes.

Microsoft Intune mapping and baseline generation are downstream implementation capabilities; they are not the project's central knowledge model.

The toolkit can:

- parse CIS Benchmark PDFs into structured `ControlRecord` data and export JSONL or CSV;
- compare structured exports from different benchmark versions;
- normalize recommendation values and deterministically map selected controls to Intune;
- classify controls as **Regular Control**, **Review Required**, or **Candidate Mandatory**;
- evaluate minimum-effective security boundary sets;
- enrich controls with Security Capabilities, Security Boundaries, Threat Scenarios, Attack Techniques, Attack Paths, and Security Outcomes;
- resolve reusable knowledge through the authoritative Security Knowledge Catalog;
- produce attack-path and boundary coverage analysis; and
- optionally request LLM suggestions only for Intune mappings already routed to manual review. Suggestions remain advisory and never replace deterministic decisions.

> **CIS benchmark content is not included.** Users must obtain benchmark documents separately and comply with the CIS Terms of Use.

## Architecture

### System architecture

![System architecture](docs/architecture.svg)

The parser establishes traceable source records. Mandatory reasoning, Security Knowledge mapping, and boundary evaluation form the analysis layer; catalog resolution then supports assessments, coverage, exports, and optional downstream Intune generation. The LLM suggestion engine is an advisory side path outside the authoritative deterministic chain.

### Security Knowledge architecture

![Security Knowledge architecture](docs/security_knowledge_architecture.svg)

The semantic chain separates source evidence, authoritative atomic `MitigationMapping` relationships, reusable catalog objects, and derived Mandatory or coverage results. External-framework mappings such as MITRE ATT&CK are controlled enrichments.

### Mandatory decision flow

![Mandatory decision flow](docs/mandatory_decision_flow.svg)

Candidate selection requires formal evidence, boundary role, attack-path support, non-compensability, applicability, and confidence. The engine never grants Definitive Mandatory status; only a human approval can do so.

### Catalog relationships

![Security Knowledge Catalog relationships](docs/security_knowledge_catalog.svg)

Generic catalog objects remain source-independent. Source recommendation identifiers exist only on mapping/evaluation objects, with `MitigationMapping` providing the authoritative source-to-knowledge relationship.

Detailed design documentation:

- [Mandatory Control Engine — Phase 1](docs/mandatory-control-phase1.md)
- [Security Knowledge Model](docs/SECURITY_KNOWLEDGE_MODEL.md)
- [Security Knowledge Catalog](docs/SECURITY_KNOWLEDGE_CATALOG.md)
- [Security Knowledge Model implementation](docs/SECURITY_KNOWLEDGE_MODEL_IMPLEMENTATION.md)
- [Security Knowledge — Phase 1](docs/security-knowledge-phase1.md)
- [Intune mapping flow](docs/mapping_flow.svg), [policy generation](docs/policy_generation.svg), and [coverage lifecycle](docs/coverage_lifecycle.svg)

## Capabilities

### CIS Benchmark Parser

The parser converts a supported CIS Benchmark PDF layout into `ControlRecord` objects. It exports one record per JSONL line or quoted UTF-8-BOM CSV for reporting and Excel interoperability.

Extracted data includes benchmark name/version/date; control ID, profile, title, assessment type, and applicability; description, rationale, impact, audit, remediation, default value, and references. Page ranges, the source PDF SHA-256, the extracted block SHA-256, parser version, and extraction timestamp preserve source traceability.

The current parser recognizes the CIS Microsoft Windows Server benchmark header and recommendation-section vocabulary implemented in `parser.py`. It should not be assumed to support an unrelated benchmark layout merely because the knowledge model is technology-independent.

### Mandatory Control Engine

The Mandatory engine is deterministic and operates on parser-produced `ControlRecord` JSONL. It does **not** encode a target number or percentage of Mandatory controls. It emits:

- **Candidate Mandatory** for a formally eligible, sufficiently evidenced, non-compensable primary boundary, complementary core member, or prerequisite with the required attack-path evidence;
- **Review Required** when applicability, evidence, comparison, overlap, completeness, or knowledge resolution remains uncertain; and
- **Regular Control** for controls that do not meet Candidate requirements and do not require adjudication.

The integrated completion rule requires at least **85% of all in-scope recommendations** to pass **and** every applicable control approved by a human as Definitive Mandatory to pass. Mandatory controls remain in the ordinary CIS denominator; they cannot occupy the maximum 15% non-compliant portion.

Boundary-set completeness is based on required security effects, prerequisites, selected alternatives, and applicability—not the number of mapped controls. Candidate conclusions also require a concrete attack path and evidence that remaining controls cannot compensate for the omitted effect.

The validated Windows Server L1 regression example contains **307 controls: 27 Candidate Mandatory, 5 Review Required, and 275 Regular Control**. This is a regression result, not a quota or desired ratio.

See [Mandatory Control Engine — Phase 1](docs/mandatory-control-phase1.md).

### Security Knowledge Engine

The [normative Security Knowledge Model](docs/SECURITY_KNOWLEDGE_MODEL.md) separates facts, mappings, inferences, and decisions. It implements typed, source-independent knowledge for:

- Security Capabilities;
- `BoundaryDefinition`, `BoundarySetDefinition`, and contextual `BoundaryEvaluation` objects;
- Threat Scenarios and reusable Attack Techniques;
- ordered Attack Paths and Security Outcomes;
- atomic `MitigationMapping` relationships with independent boundary role, mitigation role, and mitigation strength; and
- qualitative coverage semantics that distinguish complete standalone protection, complete complementary sets, supporting-only coverage, detection-only coverage, incomplete boundaries, and no effective mitigation.

Mandatory is derived from resolved knowledge and assessment context. It is not a catalog property. Risk percentages are not inferred from control counts.

### Security Knowledge Catalog

The authoritative catalog is reusable and source-independent. Its current deterministic inventory is:

| Object | Count |
|---|---:|
| Security Capabilities | 10 |
| Boundary definitions | 13 |
| Boundary-set definitions | 9 |
| Threat Scenarios | 18 |
| Attack Techniques | 12 |
| Attack Paths | 13 |
| Security Outcomes | 14 |

Catalog validation must produce **zero errors** before the catalog is treated as authoritative. Stable IDs, lifecycle state, provenance, active references, external mappings, and legacy migration coverage are validated. The committed `security-knowledge-catalog.json` is a byte-stable deterministic export; there is currently no dedicated catalog CLI entry point.

See the [catalog specification](docs/SECURITY_KNOWLEDGE_CATALOG.md) and [relationship diagram](docs/security_knowledge_catalog.svg).

### Intune Mapping

The Intune mapper is a downstream implementation engine for applicable parsed controls. It normalizes input, parses boolean/range/numeric/string recommendation values, evaluates modular Windows Server rule packs, resolves deterministic conflicts, and writes:

- `baseline.csv`;
- `manual_review.csv`;
- `conflicts.csv`;
- `intune_policies.json`; and
- `suggested_mappings.jsonl`.

Current rule packs cover account policies, audit policy, security options, Defender, firewall, credential protection, event log, and remote access for the `windows_server_2025` target. These mappings are not a claim that every benchmark recommendation has an Intune implementation.

When `--llm-fallback` is requested, only `manual_review` mappings are submitted for suggestions. Output is a proposal requiring validation and has no authority over parser facts, Mandatory classification, Security Knowledge resolution, or deterministic Intune rules.

### Benchmark Diff

The diff module compares two parser-produced JSONL exports using benchmark/profile/control identity and emits added, removed, and field-level changed records. Output can be CSV or JSONL, with optional summary and full Markdown reports.

## Current Workflow

1. Obtain and parse a CIS Benchmark PDF.
2. Produce structured `ControlRecord` JSONL.
3. Run deterministic Mandatory analysis.
4. Resolve and validate Security Knowledge relationships.
5. Review Candidate Mandatory and Review Required results.
6. Examine attack-path and boundary coverage.
7. Optionally map applicable controls to Intune and validate manual-review suggestions.
8. Compare benchmark versions when required.

## Installation

```bash
git clone https://github.com/koensmink/cis-intune-baseline-generator.git
cd cis-intune-baseline-generator
python -m pip install -e .
```

Python 3.10 or later is required.

## CLI Usage

The installed console commands are `cis-pdf2csv`, `cis-mandatory-analyze`, and `cis-intune-map`. The benchmark diff is implemented as the `cis_pdf2csv.diff` Python module. No standalone Security Knowledge/catalog CLI is currently registered; Mandatory output includes Security Knowledge enrichment and attack-path coverage.

### Parse to JSONL

```bash
cis-pdf2csv benchmark.pdf -p L1 -o controls.jsonl --format jsonl
```

### Parse to CSV

```bash
cis-pdf2csv benchmark.pdf -p L1 -o controls.csv --format csv
```

Multiple PDF inputs may be supplied to the parser. Output is sorted by benchmark name, benchmark version, and control ID.

### Mandatory analysis and coverage

```bash
cis-mandatory-analyze controls.jsonl -o mandatory-review.csv
```

This creates the full assessment, Candidate Mandatory and Review Required subsets, a summary JSON file, and an attack-path coverage JSON file alongside the requested output.

### Intune mapping

```bash
cis-intune-map controls.jsonl -o intune_out
```

Advisory suggestions for unresolved Intune mapping work can be enabled explicitly:

```bash
OPENAI_API_KEY=your_api_key cis-intune-map controls.jsonl -o intune_out --llm-fallback
```

If the flag is used without an API key, the implemented heuristic suggestion fallback is used. In either case, suggestions require human validation.

### Benchmark diff

```bash
python -m cis_pdf2csv.diff old.jsonl new.jsonl -o changes.csv \
  --report report.md --full-report report_full.md
```

Use `--format jsonl` or a `.jsonl` output path for JSONL diff output.

## Containers

Build with Docker or Podman:

```bash
docker build -t cis-pdf2csv .
podman build -t cis-pdf2csv .
```

The image entry point is the parser command:

```bash
docker run --rm -v "$PWD:/work" -w /work cis-pdf2csv benchmark.pdf -p L1 -o controls.jsonl --format jsonl
podman run --rm -v "$PWD:/work:Z" -w /work cis-pdf2csv benchmark.pdf -p L1 -o controls.jsonl --format jsonl
```

Run Mandatory analysis by overriding the entry point:

```bash
docker run --rm -v "$PWD:/work" -w /work --entrypoint python cis-pdf2csv -m cis_pdf2csv.mandatory.cli controls.jsonl -o mandatory-review.csv
podman run --rm -v "$PWD:/work:Z" -w /work --entrypoint python cis-pdf2csv -m cis_pdf2csv.mandatory.cli controls.jsonl -o mandatory-review.csv
```

Run the Intune mapper similarly:

```bash
docker run --rm -v "$PWD:/work" -w /work --entrypoint python cis-pdf2csv -m cis_pdf2csv.intune_mapper.cli controls.jsonl -o intune_out
podman run --rm -v "$PWD:/work:Z" -w /work --entrypoint python cis-pdf2csv -m cis_pdf2csv.intune_mapper.cli controls.jsonl -o intune_out
```

Run a containerized diff:

```bash
docker run --rm -v "$PWD:/work" -w /work --entrypoint python cis-pdf2csv -m cis_pdf2csv.diff old.jsonl new.jsonl -o changes.csv
podman run --rm -v "$PWD:/work:Z" -w /work --entrypoint python cis-pdf2csv -m cis_pdf2csv.diff old.jsonl new.jsonl -o changes.csv
```

`:Z` is appropriate for Podman bind mounts on SELinux-enabled hosts.

## Repository Structure

```text
src/cis_pdf2csv/
├── __main__.py, cli.py, parser.py, schema.py  # parser and CLI modules
├── diff.py
├── mandatory/
│   ├── boundary_sets.py, comparison.py, criteria.py
│   ├── pipeline.py, shortlist.py, schema.py
│   └── cli.py, exporters.py, ...
├── security_knowledge/
│   ├── catalog/
│   ├── compatibility.py
│   ├── coverage.py
│   ├── mitigation.py
│   ├── validation.py
│   └── attack_paths.py, boundaries.py, mapping.py, threats.py, ...
└── intune_mapper/
    ├── cli.py, resolver.py, normalizer.py, value_parser.py
    ├── exporters.py, llm_fallback.py
    └── rules/windows_server/

docs/
├── SECURITY_KNOWLEDGE_MODEL.md
├── SECURITY_KNOWLEDGE_CATALOG.md
├── SECURITY_KNOWLEDGE_MODEL_IMPLEMENTATION.md
├── mandatory-control-phase1.md
├── security-knowledge-phase1.md
└── architecture.svg and supporting architecture diagrams
```

## Supported Scope

These scopes are deliberately distinct:

| Area | Current scope |
|---|---|
| Parser-supported layouts | CIS Microsoft Windows Server benchmark headers and section patterns recognized by the current parser. Other layouts require validation and parser work. |
| Mandatory validated reference | The Windows Server L1 regression fixture (307 controls) validates classification parity. Phase 1 boundary knowledge covers host firewall, SMB, LDAP, NTLM, WinRM, RDP, malware protection, and privileged credential/execution families. |
| Intune mapping | Modular deterministic rule packs targeting `windows_server_2025`; unmatched or ambiguous controls remain manual review. |
| Future technology architecture | Catalog concepts are technology- and source-independent, but that architectural property does not itself make Linux, macOS, cloud, container, or other benchmark families supported. |

## Roadmap

### Current implementation

- CIS parser and structured JSONL/CSV exports;
- benchmark diff;
- deterministic Mandatory Engine;
- boundary-set reasoning;
- normative Security Knowledge Model;
- authoritative deterministic catalog;
- threat-scenario and attack-path enrichment; and
- downstream Intune mapping.

### Next phases

- normative classifier shadow mode;
- classifier cutover only after validation;
- cross-benchmark Security Knowledge mappings;
- controlled MITRE ATT&CK enrichment;
- later CWE/CVE enrichment;
- optional AI analyst and independent reviewer roles; and
- broader benchmark families after parser and mapping validation.

Planned items are not implemented capabilities and do not imply current benchmark support.

## License and Content

The source code is licensed under the MIT License. CIS benchmark content is not distributed with this repository and remains subject to CIS terms.

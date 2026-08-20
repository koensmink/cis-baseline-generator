# CIS Security Analysis and Baseline Engineering Toolkit

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

A deterministic toolkit for parsing CIS Benchmarks, evaluating Mandatory control candidates, enriching controls with reusable Security Knowledge, comparing benchmark versions, and optionally mapping supported controls to Microsoft Intune.

> **CIS benchmark content is not included.** Obtain benchmark documents separately and comply with the CIS Terms of Use. 

## What it does

- Parses supported CIS Benchmark PDFs into traceable `ControlRecord` JSONL or CSV.
- Classifies controls as **Regular Control**, **Review Required**, or **Candidate Mandatory**.
- Evaluates security boundaries, attack paths, capabilities, threats, techniques, and outcomes.
- Compares structured exports between benchmark versions.
- Maps supported Windows Server controls to Intune using deterministic rule packs.
- Uses optional LLM suggestions only for unresolved Intune mappings; suggestions remain advisory.

## Architecture

![System architecture](docs/architecture.png)


The parser establishes source evidence. Mandatory reasoning and Security Knowledge operate on structured records. Intune mapping is a downstream implementation capability and is not part of the authoritative knowledge model.

## Quick Start

### Install

```bash
git clone https://github.com/koensmink/cis-intune-baseline-generator.git
cd cis-intune-baseline-generator
python -m pip install -e .
```

Python **3.10 or later** is required.

### Parse a CIS Benchmark

```bash
cis-pdf2csv benchmark.pdf -p L1 -o controls.jsonl --format jsonl
```

### Run Mandatory analysis

```bash
cis-mandatory-analyze controls.jsonl -o mandatory-review.csv
```

### Optional: map supported controls to Intune

```bash
cis-intune-map controls.jsonl -o intune_out
```

See [CLI Usage](docs/CLI_USAGE.md) for all commands, options, container examples, benchmark diff usage, and LLM fallback.

## Core Components

### CIS Benchmark Parser

Converts supported CIS Benchmark PDF layouts into structured, evidence-bearing records. Source traceability includes page ranges, PDF and extracted-block hashes, parser version, and extraction timestamp.

Supported benchmark identity does not automatically mean every historical PDF layout is compatible.

See [CIS Benchmark Parser](docs/CIS_BENCHMARK_PARSER.md).

### Mandatory Control Engine

The deterministic Mandatory engine evaluates parser-produced controls and emits:

- **Candidate Mandatory** — formal criteria and security-boundary evidence are sufficient for human review.
- **Review Required** — applicability, evidence, overlap, completeness, or knowledge resolution is uncertain.
- **Regular Control** — Candidate criteria are not met and adjudication is not required.

The engine never grants Definitive Mandatory status automatically.

Validated Windows Server L1 regression reference:

- **307 controls**
- **27 Candidate Mandatory**
- **5 Review Required**
- **275 Regular Control**

See [Mandatory Control Engine — Phase 1](docs/mandatory-control-phase1.md).

### Security Knowledge

The Security Knowledge model provides reusable, source-independent definitions for security capabilities, boundaries, threat scenarios, attack techniques, attack paths, outcomes, and mitigation relationships.

Mandatory status is derived from resolved knowledge and assessment context; it is not a catalog property.

See:

- [Security Knowledge Model](docs/SECURITY_KNOWLEDGE_MODEL.md)
- [Security Knowledge Catalog](docs/SECURITY_KNOWLEDGE_CATALOG.md)
- [Security Knowledge Model Implementation](docs/SECURITY_KNOWLEDGE_MODEL_IMPLEMENTATION.md)

### Intune Mapping

The Intune mapper is a downstream implementation engine. Current deterministic rule packs target supported Windows Server controls and produce baseline, manual-review, conflict, policy, and optional suggestion artifacts.

Unsupported benchmark families do not run Windows-specific rules.

### Benchmark Diff

The diff module compares parser-produced JSONL exports and reports added, removed, and field-level changed controls.

See [CLI Usage](docs/CLI_USAGE.md#benchmark-diff).

## Workflow

1. Obtain a CIS Benchmark PDF.
2. Parse it into structured `ControlRecord` data.
3. Run deterministic Mandatory analysis.
4. Resolve and validate Security Knowledge relationships.
5. Review Candidate Mandatory and Review Required results.
6. Evaluate attack-path and boundary coverage.
7. Optionally map supported controls to Intune.
8. Compare benchmark versions when required.

## Supported Scope

| Area | Current scope |
|---|---|
| Parser identities | Microsoft Windows Server and Microsoft 365 Foundations identity headers |
| Mandatory reference | Windows Server L1 regression fixture and implemented boundary knowledge |
| M365 analysis | Selected domains in advisory normative shadow mode |
| Intune mapping | Deterministic Windows Server rule packs |
| Future families | Architecture is source-independent, but unsupported families are not implicitly supported |

For parser-specific compatibility and failure behavior, see [CIS Benchmark Parser](docs/CIS_BENCHMARK_PARSER.md).

## Documentation

| Document | Purpose |
|---|---|
| [CLI Usage](docs/CLI_USAGE.md) | Commands, options, examples, containers, diff, and LLM fallback |
| [CIS Benchmark Parser](docs/CIS_BENCHMARK_PARSER.md) | Parser behavior, inputs, outputs, traceability, profiles, and limitations |
| [Mandatory Control Engine — Phase 1](docs/mandatory-control-phase1.md) | Mandatory classification and boundary reasoning |
| [Security Knowledge Model](docs/SECURITY_KNOWLEDGE_MODEL.md) | Normative knowledge model |
| [Security Knowledge Catalog](docs/SECURITY_KNOWLEDGE_CATALOG.md) | Authoritative reusable catalog |
| [Security Knowledge Model Implementation](docs/SECURITY_KNOWLEDGE_MODEL_IMPLEMENTATION.md) | Implementation details |
| [v1 Release Notes](docs/V1_RELEASE_NOTES.md) | Release-specific notes |

## License and CIS Content

Source code is licensed under the [MIT License](LICENSE).

CIS benchmark content is not distributed with this repository and remains subject to CIS terms.

## Disclaimer 

CIS Benchmarks™ is a trademark of the Center for Internet Security, Inc. (CIS). This project is an independent open-source project and is not affiliated with, sponsored by, or endorsed by CIS. CIS Benchmark content is not distributed with this software.

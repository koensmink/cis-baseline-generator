# CIS Benchmark Parser

## Purpose

The CIS Benchmark Parser converts supported CIS Benchmark PDF layouts into structured `ControlRecord` objects for deterministic downstream analysis.

Its responsibility is limited to **source ingestion and normalization**. Mandatory classification, Security Knowledge reasoning, benchmark comparison, and Intune mapping are downstream functions.

```text
CIS Benchmark PDF
        |
        v
Benchmark identification
        |
        v
Recommendation extraction
        |
        v
Normalization
        |
        v
   ControlRecord
        |
        +--> Mandatory analysis
        +--> Security Knowledge
        +--> Benchmark diff
        +--> Intune mapping
```

## Input

The parser accepts one or more CIS Benchmark PDF files.

Example:

```bash
cis-pdf2csv benchmark.pdf -p L1 -o controls.jsonl --format jsonl
```

For full command syntax, see [CLI Usage](CLI_USAGE.md).

## Benchmark Identification

The current parser recognizes identity headers implemented for:

- Microsoft Windows Server benchmarks; and
- Microsoft 365 Foundations benchmarks.

Unsupported or ambiguous benchmark identity is a controlled error. The parser does not silently default an unknown benchmark to Windows Server.

A recognized benchmark identity does **not** guarantee compatibility with every historical PDF layout.

## Recommendation Extraction

For supported layouts, the parser extracts recommendation-level data into structured records.

Typical fields include:

### Benchmark metadata

- benchmark name;
- benchmark version; and
- benchmark date.

### Control identity

- control ID;
- profile;
- title;
- assessment type; and
- applicability.

### Recommendation content

- description;
- rationale;
- impact;
- audit procedure;
- remediation;
- default value; and
- references.

The exact available values depend on the source benchmark content and parser-recognized section vocabulary.

## Profiles

Use `-p/--profile` to limit extraction to a recognized profile:

```bash
cis-pdf2csv benchmark.pdf -p L1 -o controls.jsonl --format jsonl
```

When no profile is supplied:

```bash
cis-pdf2csv benchmark.pdf -o controls.jsonl --format jsonl
```

all parser-recognized profiles are included.

Profile filtering is an extraction concern and does not change Mandatory classification logic.

## Multiple Benchmarks

Multiple PDF inputs can be parsed in one operation:

```bash
cis-pdf2csv \
  benchmark_v1.pdf \
  benchmark_v2.pdf \
  -p L1 \
  -o combined.jsonl \
  --format jsonl
```

All positional inputs must be PDFs in parser mode.

Records are emitted deterministically by:

1. benchmark name;
2. benchmark version; and
3. control ID.

## Output Formats

### JSONL

JSONL is the preferred interchange format for downstream toolkit components.

```bash
cis-pdf2csv benchmark.pdf -p L1 -o controls.jsonl --format jsonl
```

Each line contains one serialized `ControlRecord`.

Typical consumers include:

- Mandatory analysis;
- Security Knowledge enrichment;
- benchmark diff; and
- Intune mapping.

### CSV

```bash
cis-pdf2csv benchmark.pdf -p L1 -o controls.csv --format csv
```

CSV output is quoted UTF-8 with BOM for Excel interoperability.

CSV is intended primarily for reporting and manual review. JSONL should be preferred where full structured records are required downstream.

## Evidence and Traceability

The parser preserves source traceability so downstream conclusions can be related back to extracted benchmark content.

Evidence metadata includes:

- source PDF page range;
- source PDF SHA-256;
- extracted recommendation-block SHA-256;
- parser version; and
- extraction timestamp.

These fields support:

- reproducibility;
- regression testing;
- change analysis;
- evidence review; and
- verification that downstream decisions are based on a specific extracted source.

## Determinism

For an unchanged supported source document and parser version, extraction should produce deterministic structured output.

Deterministic ordering and source hashes allow parser behavior to be validated independently from downstream reasoning.

## Failure Behavior

The parser should fail explicitly rather than infer an unsafe benchmark context.

Expected controlled failure cases include:

- unsupported benchmark identity;
- ambiguous benchmark identity;
- unsupported or incompatible PDF layout;
- malformed or incomplete recommendation structure; and
- input that cannot be interpreted as the requested parser mode.

Failure to recognize an identity must not result in Windows Server rules being applied implicitly.

## Parser Boundaries

The parser does **not** decide whether a recommendation is Mandatory.

It also does not establish:

- minimum-effective security boundaries;
- attack-path coverage;
- authoritative Security Knowledge relationships;
- Intune implementation support; or
- compliance status.

Those are separate downstream responsibilities.

## Compatibility

Current identity support is intentionally narrower than the long-term technology model.

| Area | Status |
|---|---|
| Microsoft Windows Server identity headers | Recognized |
| Microsoft 365 Foundations identity headers | Recognized |
| Every historical layout of recognized families | Not guaranteed |
| Unsupported benchmark families | Explicit failure |
| Automatic fallback to Windows Server | Not permitted |

Additional benchmark families should be considered supported only after parser identity, layout, extraction, and regression behavior have been validated.

## Downstream Flow

A typical processing sequence is:

```text
PDF
 |
 v
ControlRecord JSONL
 |
 +--> cis-mandatory-analyze
 |
 +--> Security Knowledge resolution
 |
 +--> python -m cis_pdf2csv.diff
 |
 +--> cis-intune-map
```

See [CLI Usage](CLI_USAGE.md) for command examples.

## Related Documentation

- [CLI Usage](CLI_USAGE.md)
- [Mandatory Control Engine — Phase 1](mandatory-control-phase1.md)
- [Security Knowledge Model](SECURITY_KNOWLEDGE_MODEL.md)
- [Security Knowledge Catalog](SECURITY_KNOWLEDGE_CATALOG.md)

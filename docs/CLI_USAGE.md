# CLI Usage

This document contains the operational command reference for the CIS Security Analysis and Baseline Engineering Toolkit.

The package currently installs three console commands:

| Command | Purpose |
|---|---|
| `cis-pdf2csv` | Parse CIS Benchmark PDFs or dispatch a single JSONL input to the Intune mapper |
| `cis-mandatory-analyze` | Run deterministic Mandatory-control analysis and attack-path coverage |
| `cis-intune-map` | Map parser-produced JSONL to supported Intune artifacts |

Benchmark diff is available through `python -m cis_pdf2csv.diff`.

There is currently no standalone Security Knowledge or catalog CLI.

## Installation

```bash
git clone https://github.com/koensmink/cis-intune-baseline-generator.git
cd cis-intune-baseline-generator
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

Current deterministic mappings target supported Windows Server controls. Unsupported benchmark families are routed to manual review instead of running Windows-specific rules.

## Optional Intune LLM Fallback

LLM assistance applies only to controls unresolved after deterministic mapping. Suggestions are advisory and require validation.

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
- benchmark diff: [`src/cis_pdf2csv/diff.py`](../src/cis_pdf2csv/diff.py)

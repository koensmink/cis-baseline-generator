# Baseline Assessment

`cis-baseline-assess` joins the desired CIS baseline with the provenance-bearing
snapshot produced by `cis-environment-scan`. It is a downstream assessment layer;
it does not parse PDFs, change source controls, or deploy configuration.

## Workflow

```text
CIS PDF -> cis-pdf2csv -> controls.jsonl
                                  |
environment -> cis-environment-scan -> current-state.json
                                  |
                                  v
                         cis-baseline-assess
                                  |
                                  v
                     assessment + action queue
```

```bash
cis-baseline-assess controls.jsonl \
  --current-state current-state.json \
  -o assessment
```

## Decision model

The assessor fails closed:

| Status | Meaning |
|---|---|
| `declared_compliant` | A verified authoritative mapping and comparable declared value match |
| `declared_non_compliant` | A verified authoritative mapping and comparable declared value differ |
| `potential_conflict` | More than one declared value was observed; assignment overlap is not proven |
| `not_measurable` | The mapping, observation, or value is insufficient for a safe conclusion |
| `manual_evidence_required` | CIS marks the control as manual |
| `exception_active` | A current approved exception applies |
| `not_applicable` | A current approved not-applicable decision applies |

An unknown benchmark family cannot automatically become measurable. Intune
mappings produced by heuristics or AI remain unverified and therefore cannot
produce a compliance conclusion.

The parser's `default_value` is never treated as the desired CIS state. The
assessor only derives a desired value from an explicit recommendation in the CIS
title, and the existing authoritative mapper must then verify the complete
mapping and value type.

## Trust boundary

The scanner observes declared policies and assignments. It does not calculate
Microsoft Intune resultant policy for every device. A match is therefore called
`declared_compliant`, and every such record includes
`EFFECTIVE_STATE_NOT_OBSERVED`.

Missing settings produce `not_measurable`, not `declared_non_compliant`.
Different values in multiple policies produce `potential_conflict`; the assessor
does not assume their assignments overlap.

A partial scanner result is exported for investigation, but the command returns
exit status `2` so automation cannot mistake it for a complete assessment.

## Approved exceptions

Supply a JSON array using `--exceptions`:

```json
[
  {
    "control_id": "1.1",
    "benchmark_name": "CIS Microsoft Windows Server 2025 Benchmark",
    "benchmark_version": "1.0",
    "decision": "exception_active",
    "rationale": "Legacy application requires the current state",
    "approved_by": "Security Board",
    "expires_at": "2026-12-31T23:59:59Z",
    "compensating_controls": ["Restricted network segment", "EDR monitoring"]
  }
]
```

`expires_at` must contain a timezone. More than one active exception matching the
same control is rejected as ambiguous. Expired exceptions do not suppress the
normal assessment and are exposed through `EXCEPTION_EXPIRED`.

Use `--at-time` to reproduce a prior assessment exactly:

```bash
cis-baseline-assess controls.jsonl \
  --current-state current-state.json \
  --exceptions exceptions.json \
  --at-time 2026-09-04T12:00:00Z \
  -o assessment
```

## Outputs

- `assessment.csv` and `assessment.jsonl`: control-level results;
- `assessment.json`: full result and provenance;
- `action-required.csv`: implementation and review queue;
- `assessment-summary.json`: automation and reporting summary.

Every result retains benchmark-scoped source identity, mapping status, desired
and observed values, policy IDs, reason codes, and exception evidence.

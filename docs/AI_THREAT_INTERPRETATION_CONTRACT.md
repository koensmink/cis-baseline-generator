# AI Threat Interpretation Contract

Phase 4A defines the provider-neutral, fail-closed contract. Phase 4B adds one
optional OpenAI adapter behind that contract. Neither layer participates in control
classification or prioritization, and neither retrieves source documents.

## Authority boundary

The only AI-authorized output is an untrusted `ProposedThreatInterpretation`.
It may summarize caller-supplied material, extract dates and source references,
identify uncertainty, and propose existing threat scenario, technique, and attack
path IDs. Structural validation prohibits CIS control IDs, Mandatory decisions,
base proposals, threat relevance, advisory actions, customer exposure claims, and
boundary-completeness decisions.

Unknown and malformed catalog IDs block validation. Inactive catalog IDs require
review and are never silently replaced. The catalog remains immutable.

## Source document and evidence grounding

`ThreatAdvisoryDocument` represents caller-supplied content. Its SHA-256 content
hash is checked deterministically; no retrieval is performed. Advisory content is
untrusted, including text that resembles model or system instructions.

Every material proposal has a concise `InterpretationEvidenceAssertion` with a
source locator, support type, confidence, and explicit-versus-inferred state. Large
source excerpts are not copied. Source-grounded interpretation is the default;
`external_model_knowledge` is blocking and excluded from conversion.

`observed` and `actively_exploited` require explicitly stated evidence. Critical
severity, exploitability, proof-of-concept status, or model confidence cannot imply
exploitation. Affected technology also requires explicit grounding. Severity,
confidence, and activity remain independent.

## Confidence calibration

The authoritative `Confidence` enum is reused. Direct, unambiguous evidence may
retain High confidence. Strongly implied material claims cap confidence at Medium;
inferred or speculative material claims cap it at Low. Severity does not change the
cap. A converted `ThreatContext` cannot exceed validated interpretation confidence.

## Validation and approval

Machine validation and human approval are separate. Schema-valid and catalog-valid
output remains non-participating while approval is `pending`. `rejected` and
`needs_revision` proposals cannot convert. Conversion requires a matching explicit
approval, named reviewer and supplied review time, non-blocking validation, target
ThreatContext identity, and explicit accepted/rejected assertion sets.

Only accepted assertions populate `ThreatContext`. Unknown, rejected, unsupported,
sensitive, or forbidden material is excluded. Provenance records the document,
interpretation, approval, reviewer, and revision chain. Raw prompts, provider
secrets, and copied source text are not carried forward.

## Fail-closed and adversarial handling

Blocking findings cover forbidden fields, unknown or malformed catalog IDs,
ungrounded activity or technology, missing evidence, prompt-injection output,
external model knowledge, sensitive output, input/contract mismatches, and missing
approval. Input findings identify possible secrets, personal data, or adversarial
instructions for review; Phase 4A intentionally does not implement full DLP.
Source instructions are always evidence content and can never alter authority
policy or authorize an external action.

## Identity and reproducibility

Document and interpretation IDs are caller-supplied or derived from stable identity
components. Interpretation identity does not hash the complete output;
`interpretation_revision` is separate. Provider, model, model version, prompt,
contract, policy, generation-parameter identity, and input hash are retained. All
contract models serialize with sorted keys and canonical collection ordering,
without implicit timestamps or random identifiers.

## Phase 4B provider adapter

`ThreatInterpretationProvider` is provider-neutral. The first implementation uses
the OpenAI Responses API with strict JSON Schema output, no tools, no requested or
retained reasoning trace, an explicit timeout, `store=false`, and bounded retries
for transient failures only. Provider-specific imports remain isolated.

The deterministic request builder supplies only:

- trusted contract and authority-policy rules;
- active threat-scenario, technique, and attack-path IDs and names; and
- the caller-supplied advisory metadata and content, clearly labeled untrusted.

It never sends CIS controls, Mandatory output, priority output, environment secrets,
or customer data by default. The live catalog still validates every returned ID.
Markdown, free text, malformed JSON, schema mismatches, forbidden fields, and
blocking Phase 4A findings fail closed without repair.

Credentials come only from `OPENAI_API_KEY` or an explicit in-memory caller value.
They are not logged, serialized, placed in provenance, or included in errors.
Provider privacy policy records only caller-configured region/retention identifiers,
training-use permission, and whether sensitive or customer data is allowed; it does
not claim provider guarantees. The default rejects potential secrets and personal
data before any request.

## Operator workflow

1. Obtain advisory text out of band and save it locally.
2. Run `cis-threat-interpret` with a structured-output-capable model.
3. Inspect `proposed-threat.json` and its summary.
4. Perform human approval and explicit conversion using the Phase 4A gate.
5. Export the approved `ThreatContext` separately.
6. Run `cis-threat-analyze` with that approved context.

```bash
OPENAI_API_KEY="<runtime-secret>" cis-threat-interpret advisory.txt \
  --source-type vendor_advisory \
  --source-name "Example Vendor" \
  --source-reference "ADV-2026-001" \
  --model "<structured-output-capable-model>" \
  --generated-at 2026-08-24T12:00:00Z \
  -o proposed-threat.json
```

The command accepts no URL and performs no fetching or live-feed ingestion. It
writes `proposed-threat.json` with proposal, validation, and audit metadata plus
`proposed-threat-summary.json`. Full source content and full raw provider responses
are not persisted. Exit codes are 0 for a valid proposal, 2 for local input or
configuration errors, 3 for provider/network failures, and 4 for blocked provider
output.

Provider output may be nondeterministic even with fixed generation parameters.
Audit metadata retains provider/model identity, prompt and contract versions,
generation-parameter identity, input and vocabulary hashes, request ID, and raw
response hash. Deterministic behavior resumes after strict parsing at the Phase 4A
boundary. No proposal is approved or converted automatically.

For a manual live smoke test, use invented non-sensitive advisory text, configure a
model that supports strict structured output, run the command above, and inspect
both artifacts. Live calls are never part of automated tests.

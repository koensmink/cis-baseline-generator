# AI Threat Interpretation Contract

Phase 4A defines a provider-neutral, fail-closed boundary around future AI
interpretation. It does not invoke a model, import a provider SDK, retrieve a
document, or participate in control classification or prioritization.

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

## Provider boundary

No provider integration exists in Phase 4A. Phase 4B would require a separately
reviewed adapter that accepts caller-supplied documents, applies this versioned
contract, sends raw structured output through payload validation, and adds explicit
privacy, retention, credential, error, and reproducibility controls. It must not
bypass human approval or write Mandatory status, threat relevance, advisory action,
or control mappings.

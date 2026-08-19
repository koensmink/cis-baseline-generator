# Security Knowledge Model

This document defines the authoritative semantic model for the Security
Knowledge Engine. The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**,
and **MAY** are normative.

## 1. Purpose

The Security Knowledge Model provides a technology-independent and
source-independent knowledge layer for:

- recommendations originating in CIS benchmarks;
- Mandatory-control selection;
- attack-path analysis;
- explanations of risk reduction and non-compensability;
- comparison of related controls;
- coverage analysis; and
- future mappings to other security baselines.

The current implementation has validated Windows Server reference behavior and
secondary advisory Microsoft 365 identity/authentication and
application/workload-identity slices. The
ontology itself MUST NOT be Windows-specific, CIS-specific, product-specific, or
tied to one parser. Windows Server names belong in source records, technology
scopes, boundary instances, and mapping rules—not in the definitions of generic
capabilities, threats, techniques, outcomes, or risks.

Mandatory classification is a derived output of this model. It is not the
central knowledge object and MUST NOT be used as the source from which threats,
attack paths, capabilities, or boundaries are defined.

## 2. Design principles

1. **Deterministic before probabilistic.** An explicit deterministic rule MUST
   take precedence over a probabilistic suggestion. Probabilistic results MUST
   remain identifiable as such and MUST NOT become source facts.
2. **Evidence traceability.** Every material mapping and decision MUST identify
   the source fields and source location that support it.
3. **Stable identifiers.** Catalog objects MUST have immutable identifiers.
   Display names and descriptions MAY evolve through versioning.
4. **Technology-independent concepts.** Capabilities, threat semantics,
   techniques, paths, outcomes, and risks MUST be expressed independently of a
   specific product wherever the concept is reusable.
5. **Separation of source facts and inferred knowledge.** Parsed facts,
   normalized values, deterministic mappings, analyst assertions, and decisions
   MUST remain distinguishable.
6. **No title-only classification.** A title MAY select a potential rule but
   MUST NOT, by itself, establish a capability, boundary, attack path, or
   Mandatory decision.
7. **Many-to-many relationships.** A control MAY support several capabilities
   and paths; a path MAY be mitigated by several controls and boundary sets.
8. **Explicit confidence.** Confidence MUST be recorded for each independently
   inferred relationship, rather than inferred from a single global score.
9. **Explicit applicability.** Universal, conditional, and unresolved
   applicability MUST remain distinguishable.
10. **Explicit uncertainty.** Missing evidence, unresolved alternatives,
    ambiguous scope, and mapping disagreement MUST be represented, not hidden by
    a default mapping.
11. **Explainable Mandatory decisions.** A Candidate Mandatory proposal MUST be
    reproducible from evidence, boundary role, attack-path effect, applicability,
    exclusions, and confidence.
12. **No quota.** The engine MUST NOT encode a fixed target count or percentage
    of Mandatory controls.
13. **Integrated CIS scoring.** Mandatory controls remain part of the normal CIS
    score and denominator. They do not receive a separate coverage percentage.
14. **Completion rule.** All applicable controls approved as Definitive
    Mandatory MUST pass and MUST NOT fall within the maximum non-compliant
    portion of the baseline. This requirement supplements, but does not replace,
    the baseline's ordinary completion threshold.

## 3. Conceptual layers

The conceptual evaluation order is:

```text
Source Recommendation
    ↓
Security Capability
    ↓
Security Boundary
    ↓
Threat Scenario
    ↓
Attack Technique
    ↓
Attack Path
    ↓
Security Outcome
    ↓
Mitigation Mapping
    ↓
Mandatory Decision
```

Risk is a contextual branch, not a mandatory step in that chain:

```text
Threat Scenario + Security Outcome + context + existing mitigations → Risk
```

This order expresses how an assessment should be explained. It is not a strict
storage hierarchy. Relationships at every layer MAY be many-to-many. For
example, one source recommendation may enforce two capabilities, a threat
scenario may involve several techniques, and one attack path may traverse
several boundaries. Implementations MUST preserve object identity and explicit
links rather than duplicating an upstream object into every downstream object.

The layers distinguish four kinds of information:

- **Fact:** evidence copied or normalized from an authoritative source.
- **Mapping:** a versioned relationship asserted between identified objects.
- **Inference:** a conclusion produced by a documented rule or reviewer.
- **Decision:** a context-dependent classification such as Candidate Mandatory.

## 4. Source Recommendation

A Source Recommendation is the evidence-bearing recommendation supplied by a
source framework. For the current implementation it is the parser-produced CIS
`ControlRecord`.

Its source and provenance fields include, at minimum:

- source framework;
- benchmark identity, version, and date;
- profile;
- control ID;
- title;
- description;
- rationale;
- impact;
- audit procedure;
- remediation;
- default value;
- applicability;
- assessment type;
- page range;
- source-document hash and control-block hash; and
- parser version and extraction timestamp.

Source recommendation identity MUST be scoped by source framework, benchmark
identity, benchmark version, profile, and control ID. A bare control ID is not a
globally unique identity.

Values fall into three categories:

- **Raw source values** reproduce what the source document states, subject only
  to lossless extraction representation.
- **Normalized values** standardize whitespace, enums, identifiers, or parsed
  recommendation values while retaining a link to the raw value and the
  normalization method.
- **Derived values** include criteria, family, related-control relationships,
  boundary membership, mappings, confidence, and decisions.

Source-derived facts MUST never overwrite raw source values. Corrections MUST be
represented as a new extraction, a normalization record, or an explicit
adjudication with provenance. References and audit commands MAY support evidence
traceability but MUST NOT independently activate a security criterion or mapping.

## 5. Security Capability

A Security Capability is a technology-independent defensive ability. It states
what protection can be provided, not how a particular product implements it.

Every capability object MUST define:

- `identifier` — immutable stable ID;
- `name` — concise human-readable label;
- `definition` — technology-independent meaning;
- `security_objective` — the condition the capability seeks to preserve;
- `examples` — non-normative implementations from more than one technology
  where practical;
- `exclusion_boundaries` — related concepts that do not, by themselves, satisfy
  the capability; and
- `lifecycle_status` — draft, active, deprecated, or superseded.

The initial catalog is:

| ID | Name | Definition and security objective | Examples | Exclusion boundaries | Status |
|---|---|---|---|---|---|
| CAP-01 | Identity and authentication protection | Validates identities and resists weak, anonymous, intercepted, or replayed authentication. Objective: only adequately verified identities cross an access boundary. | Strong authentication, refusal of legacy credentials, signed authentication exchange. | Account naming, identity display, authorization without identity validation. | active |
| CAP-02 | Credential protection | Prevents disclosure, extraction, unsafe delegation, or recoverable storage of credentials and derivatives. Objective: reusable authentication material remains confidential. | Isolated secrets, protected credential processes, non-reversible password storage. | Password cosmetics, authentication logging alone, generic data encryption without credential relevance. | active |
| CAP-03 | Privileged execution control | Mediates and restricts transitions into privileged execution. Objective: administrative authority is granted only through an enforced elevation boundary. | Elevation consent, privileged-token mediation, protected elevation interface. | General account management, UI prompts without enforcement, malware scanning alone. | active |
| CAP-04 | Network boundary protection | Restricts network paths and traffic crossing a protected-system boundary. Objective: unauthorized connectivity cannot reach protected assets. | Default-deny inbound policy, protocol restriction, segmentation enforcement. | Network logging alone, notification settings, tuning that does not alter reachability. | active |
| CAP-05 | Secure remote management | Protects authentication, authorization, credential handling, and transport for remote administration. Objective: management interfaces cannot be reached or abused through an inadequately protected channel. | Protected management transport, strong remote authentication, restrictive remote-logon rights. | Session usability, temporary-folder handling, generic local administration. | active |
| CAP-06 | Application and code execution control | Restricts whether untrusted applications, scripts, macros, or active content may execute. Objective: unauthorized code does not obtain an execution path. | Allowlisting, script restriction, macro enforcement, sandbox entry. | Detection after execution, scan scheduling, application inventory alone. | active |
| CAP-07 | Malware prevention and response | Prevents, contains, and responds to malicious software behavior. Objective: active protection remains capable of blocking malicious execution and evasion. | Real-time protection, behavior monitoring, network block mode, EDR blocking. | Supplemental scan coverage, UI visibility, scheduling, notifications. | active |
| CAP-08 | Cryptographic and transport protection | Provides confidentiality, integrity, and peer authenticity for data in transit or storage. Objective: protected information cannot be read or modified through a weak channel. | Signing, sealing, approved encryption, protected transport. | Mere mention of encryption, audit-only checks, encryption that does not protect the relevant boundary. | active |
| CAP-09 | Security monitoring and investigation | Preserves visibility and evidence required to detect and investigate harmful activity. Objective: material security events remain observable and reconstructable. | Essential audit source, tamper-resistant security logging, investigation evidence. | Log cosmetics, size tuning without adequacy evidence, redundant telemetry. | active |
| CAP-10 | Data protection | Protects data against unauthorized disclosure, alteration, or loss throughout its lifecycle. Objective: data security properties are preserved according to sensitivity and use. | Storage protection, access restriction, integrity enforcement, recoverability controls. | Credential-only protection where no broader data objective exists, generic availability tuning. | active |

Capabilities are not products, settings, source controls, boundary sets, attack
paths, compliance requirements, or Mandatory decisions.

## 6. Security Boundary

A Security Boundary is an enforcement surface at which access, execution,
information flow, privilege, or security state is controlled. Boundary semantics
are represented by three separate objects.

Examples include SMB session security, LDAP channel security, NTLM session
security, a host firewall, WinRM, RDP, a malware-protection stack, and a
privileged-execution boundary.

### BoundaryDefinition

A `BoundaryDefinition` is the stable, generic security-boundary catalog object.
It MUST use `BND-<DOMAIN>-<TOKEN>`, and MUST own:

- name, definition, and security objective;
- technology scope, expressed generically enough to support multiple products;
- required security effects or sub-boundaries;
- related capability IDs;
- generic compensation constraints; and
- lifecycle status and catalog provenance.

It MUST NOT own a benchmark profile, deployment state, selected implementation,
or evaluation result.

### BoundarySetDefinition

A `BoundarySetDefinition` is a generic minimum effective control-effect set that
implements one `BoundaryDefinition`. It MUST use `BS-<DOMAIN>-<TOKEN>`, and MUST
own:

- its referenced `boundary_definition_id`;
- required core effects and prerequisites;
- allowed alternative-effect groups;
- optional supporting effects;
- generic completeness predicates; and
- lifecycle status and catalog provenance.

A boundary MAY have multiple active boundary-set definitions when materially
different implementations can enforce the same boundary. A boundary-set
definition MUST NOT contain benchmark control IDs.

### BoundaryEvaluation

A `BoundaryEvaluation` is the benchmark-specific or environment-specific result
of applying a boundary definition and, optionally, a boundary-set definition. It
MUST use `BEV-<DOMAIN>-<TOKEN>` and contain:

- `boundary_definition_id`;
- optional `boundary_set_definition_id`;
- decision scope, source benchmark identity and profile;
- applicability mode and deployment state;
- selected source recommendations and selected alternatives;
- satisfied and missing effects and prerequisites;
- completeness state;
- compensating-control evaluation IDs;
- residual attack-path statement;
- evaluation confidence; and
- evaluation provenance.

Ownership is normative: `BoundaryDefinition` owns technology scope and generic
compensation constraints; `BoundarySetDefinition` owns minimum-set structure,
alternatives, and generic completeness rules; `BoundaryEvaluation` owns
benchmark profile, deployment applicability, selected alternatives, evaluated
completeness, accepted compensation, and residual exposure.

The `boundary_role` enum is:

- `standalone_primary_boundary`: independently enforces the relevant boundary;
- `boundary_set_core_member`: enforces a distinct required sub-boundary;
- `prerequisite`: must exist for the boundary or a core member to function;
- `supporting_hardening`: reduces exposure but does not complete the boundary;
- `fine_tuning`: adjusts parameters of an already established boundary;
- `detection_only`: observes events without enforcing the preventive boundary;
- `information_hiding`: changes exposed information or presentation without
  materially enforcing access;
- `operational`: affects administration, lifecycle, or usability without
  constituting the security boundary.

Related controls MUST be distinguished as follows:

- **Duplicate controls** enforce the same sub-boundary with the same effect and
  applicability. They require deduplication or analyst selection and cannot both
  be claimed as the unique primary mitigation.
- **Complementary controls** enforce different effects required by the same
  minimum effective boundary. All may be core members.
- **Alternative controls** provide mutually substitutable implementations of
  the same required effect. The selected alternative depends on applicability
  or architecture.
- **Supporting controls** improve strength, observability, resilience, or
  operability but do not complete the boundary.

Completeness MUST be evaluated from required effects, prerequisites, selected
alternatives, and applicability—not from the number of mapped controls.

## 7. Threat Scenario

A Threat Scenario is a concrete, understandable adversarial situation. It binds
an attacker position and objective to an asset, weakness, action, and plausible
effect. It MUST remain understandable without MITRE ATT&CK terminology.

Example: unsigned directory authentication permits an attacker with a network
position to relay a victim's authentication exchange to a directory service and
act with the victim's privileges.

A threat scenario MUST define:

- `threat_scenario_id`;
- `name` and `description`;
- `attacker_position` or actor assumptions;
- `preconditions`;
- `targeted_assets`;
- `abused_weakness`;
- `attacker_objective`;
- `immediate_outcome`;
- `impact`;
- `related_technique_ids`;
- `related_boundary_ids`;
- typed `evidence_references`; and
- `confidence`.

Threat scenarios SHOULD be split when attacker position, required privilege,
target asset, or immediate outcome changes materially. Product-specific details
MAY be attached as scenario variants rather than embedded in a generic threat.

## 8. Attack Technique

An Attack Technique is a reusable adversary behavior. It describes how an
attacker acts, independently of one complete end-to-end path.

A technique object MUST define:

- `technique_id` — the internal immutable identifier;
- `name` and `description`;
- `tactic_or_stage`;
- `external_mappings`, including framework name and version;
- `affected_technologies` where relevant;
- `prerequisites`; and
- `confidence` for each external mapping.

Internal technique identity, external framework mappings, MITRE ATT&CK IDs, and
product-specific implementation details are distinct. A MITRE technique is not
an attack path. Multiple threat scenarios may map to one technique, and one
scenario may involve multiple techniques. External mappings are enrichment,
not authoritative source facts, and MUST include framework/version provenance.
Attack techniques are optional enrichments for active paths; they do not replace
a concrete Threat Scenario.

## 9. Attack Path

An Attack Path is an ordered sequence of adversary steps that can lead from an
entry condition through intermediate conditions to a security outcome. A path
connects threat scenarios and techniques; it is broader than one technique but
bounded enough to have coherent entry conditions, stages, mitigations, and
residual exposure.

The initial paths are:

- AP-001 Credential relay and authentication interception
- AP-002 Credential extraction from operating-system memory
- AP-003 Lateral movement over administrative protocols
- AP-004 Abuse of remote-management interfaces
- AP-005 Malicious code and script execution
- AP-006 Malware evasion and protection disablement
- AP-007 Unauthorized inbound network access
- AP-008 Privilege elevation through weak consent boundaries
- AP-009 Plaintext or weakly protected credential storage
- AP-010 Security-event suppression or loss of forensic evidence

An attack path MUST define:

- `attack_path_id`;
- `name` and `description`;
- `ordered_stages`;
- `entry_conditions`;
- `intermediate_conditions`;
- `attacker_goals`;
- `affected_assets`;
- `security_outcome_ids`;
- `related_threat_scenario_ids`;
- `related_technique_ids`;
- `related_boundary_ids`;
- `residual_path_when_partially_mitigated`; and
- `confidence`.

Every active AttackPath MUST reference at least one active ThreatScenario.
Technique-only paths MAY exist only with `draft` status and are ineligible for
Candidate Mandatory decisions. Techniques remain optional enrichment.

AttackPath MUST remain a reusable catalog object. It MUST NOT contain source
control mapping IDs. AttackPath-to-MitigationMapping relationships are derived
by querying MitigationMapping objects. If generic curated mitigations are later
needed, they MUST be separate catalog objects and MUST NOT be represented as
source-control mappings.

A path SHOULD be split when it has materially different entry conditions,
attacker privileges, target assets, stage order, primary boundaries, or security
outcomes. A path MUST NOT become a catch-all category merely because controls
share words or a broad tactic. Variants MAY share techniques and outcomes while
remaining separate attack paths.

## 10. Security Outcome and Risk

A Security Outcome is the technical result produced when an attack path
succeeds. Examples are credential theft, unauthorized authentication, privilege
escalation, lateral movement, remote code execution, loss of confidentiality,
loss of integrity, loss of availability, domain compromise, and loss of
forensic evidence.

An outcome object MUST define an immutable ID, name, description, affected
security property, affected asset classes, severity factors, and lifecycle
status. Outcomes describe results; they do not include likelihood.

Risk is the contextual combination of:

- a threat;
- a vulnerability or weakness;
- an affected asset;
- likelihood factors;
- technical and business impact;
- existing mitigations; and
- residual exposure.

No generic numeric risk score is defined in this phase. A qualitative risk
explanation MUST contain:

- `risk_id`;
- `scenario_id`;
- `affected_asset_class`;
- `technical_impact`;
- `business_impact`;
- `likelihood_factors`;
- `existing_mitigation_mapping_ids`; and
- `residual_risk_statement`.

Risk MUST be scoped to an environment or declared reference context. A source
recommendation's rationale is evidence about a general security concern; it is
not automatically a customer-specific risk assessment.

The relationships are normative:

```text
AttackPath → SecurityOutcome
ThreatScenario + SecurityOutcome + context + existing mitigations → Risk
```

A generic Mandatory decision MAY rely on a SecurityOutcome and does not require
a customer-specific Risk object.

## 11. Mitigation Mapping

A Mitigation Mapping is the evidence-bearing relationship between a source
control and reusable security knowledge. It is atomic. Each mapping MUST contain
singular:

- `mapping_id`;
- `source_recommendation_id` with full source scope;
- `capability_id`;
- `boundary_definition_id`;
- optional `boundary_set_definition_id`;
- optional `threat_scenario_id`;
- `attack_path_id`;
- `attack_stage`;
- `boundary_role`;
- `mitigation_role`;
- `mitigation_strength`;
- `enforced_sub_boundary`;
- `attack_path_if_omitted`;
- `non_compensability_reason`;
- `applicability_mode` and applicability expression;
- `confidence`; and
- mapping evidence and provenance.

Lists are permitted only for `corroborating_technique_ids`,
`evidence_reference_ids`, and `compensating_control_evaluation_ids`. If a source
recommendation applies to multiple attack paths, stages, capabilities, or
boundaries, the engine MUST create multiple atomic mapping objects.
`threat_scenario_id` is optional for general mappings, but MUST be populated for
any mapping used as Candidate Mandatory evidence.

The three role dimensions are independent:

- `boundary_role`: `standalone_primary_boundary`,
  `boundary_set_core_member`, `prerequisite`, `supporting_hardening`,
  `fine_tuning`, `detection_only`, `information_hiding`, or `operational`;
- `mitigation_role`: `prevent`, `restrict`, `isolate`, `protect`, `detect`,
  `investigate`, or `recover`; and
- `mitigation_strength`: `primary`, `complementary`, or `supporting`.

No value from one dimension may be serialized into another dimension.

Applicability modes are:

- `universal` — applies throughout the declared benchmark scope;
- `mandatory_when_deployed` — applies whenever the identified technology or
  role is deployed; and
- `unresolved` — available evidence does not establish applicability.

Deployment state is independently represented as `deployed`, `not_deployed`,
`unknown`, or `not_evaluated`. Decision scope is `benchmark` or `environment`.

Valid combinations and outcomes are:

| Decision scope | Applicability mode | Deployment state | Permitted result |
|---|---|---|---|
| benchmark | universal | not_evaluated | Normal benchmark decision |
| benchmark | mandatory_when_deployed | not_evaluated or unknown | Conditional Candidate Mandatory is permitted when all mapping confidence is High; the condition MUST be explicit |
| benchmark | unresolved | any | Review Required |
| environment | universal | deployed | Normal environment decision |
| environment | universal | not_deployed | Not applicable in that environment; not Definitive Mandatory there |
| environment | mandatory_when_deployed | deployed | Candidate or human-approved Definitive Mandatory is permitted |
| environment | mandatory_when_deployed | not_deployed | Not applicable in that environment |
| environment | universal or mandatory_when_deployed | unknown or not_evaluated | Review Required |
| environment | unresolved | any | Review Required |

Other combinations are invalid. `deployment_state` MUST NOT be used to rewrite
the source applicability fact; it belongs to BoundaryEvaluation or decision
context.

Title matching alone is insufficient. A mapping MUST use a recognized boundary
or corroborating behavioral evidence from description, rationale, impact,
remediation, or another permitted source fact. References and audit commands
MUST NOT independently create a mapping. One mapping SHOULD express one coherent
control–capability–path–stage assertion.

### CompensatingControlEvaluation

Compensation is an explicit evaluation, not free text on a control. A
`CompensatingControlEvaluation` MUST contain:

- `evaluation_id`;
- `source_mapping_id`;
- `candidate_compensating_control_id` with full source scope;
- `replaced_security_effect`;
- `protected_scope`;
- `equivalence_type`: `full`, `conditional`, `partial`, or `none`;
- prerequisites;
- applicability;
- typed evidence references;
- confidence;
- `residual_attack_path`;
- reviewer;
- status and provenance.

Only `full` equivalence, or `conditional` equivalence explicitly accepted by an
authorized reviewer with all conditions satisfied, may satisfy a compensation
review. `partial` and `none` leave the omitted path non-compensated. A control
whose boundary role is `supporting_hardening`, `fine_tuning`, `detection_only`,
`information_hiding`, or `operational` MUST NOT be treated as full compensation
for a missing primary or core security effect.

## 12. Mandatory Decision

A Mandatory Decision is a derived conclusion over the complete knowledge chain.
Its values are:

- `Regular Control`;
- `Review Required`;
- `Candidate Mandatory`; and
- `Definitive Mandatory`.

The deterministic engine MAY emit the first three values. `Definitive
Mandatory` always requires recorded human approval and MUST NOT be emitted
automatically.

Candidate Mandatory requires all of the following:

- formal eligibility;
- sufficient source evidence;
- at least one explicit Security Capability;
- a concrete, active Security Boundary;
- at least one active Threat Scenario and its active Attack Path;
- `boundary_role` equal to `standalone_primary_boundary`,
  `boundary_set_core_member`, or `prerequisite`;
- `mitigation_strength` equal to `primary` or `complementary`;
- a concrete attack path left open when the control is omitted;
- a boundary-level non-compensability explanation;
- resolved applicability;
- sufficient mapping and decision confidence; and
- no blocking exclusion.

“Reliable” and “sufficient confidence” are not implementation-defined terms.
Candidate Mandatory requires `High` confidence for every required link:

| Confidence dimension | Candidate Mandatory threshold |
|---|---|
| source extraction | High |
| capability mapping | High |
| boundary mapping and BoundaryEvaluation | High |
| threat-scenario mapping | High |
| attack-path mapping | High |
| MitigationMapping | High |
| final Mandatory decision | High |

Any required dimension below High produces Review Required. For
`mandatory_when_deployed`, a benchmark-scoped conditional Candidate Mandatory is
permitted only when every mapping dimension is High. An environment-scoped
Definitive Mandatory decision additionally requires `deployment_state =
deployed`. `unknown` or `not_evaluated` deployment state at environment scope
produces Review Required.

`Review Required` applies when an attack-path mapping is missing, boundary role
is unresolved, applicability is unresolved, alternatives or duplicates cannot
be distinguished, source evidence is insufficient, or confidence is below the
required threshold.

Security relevance alone is not sufficient. A control may be relevant to a
threat yet remain supporting, redundant, operational, detection-only, or
reasonably compensable. Such a control MUST NOT become Candidate Mandatory for
relevance alone.

## 13. Confidence and provenance

Confidence MUST be recorded separately for:

- source extraction;
- capability mapping;
- boundary mapping;
- threat-scenario mapping;
- technique mapping;
- attack-path mapping; and
- Mandatory decision.

The allowed values are `High`, `Medium`, and `Low`. Confidence criteria MUST be
defined per object or relationship type. Confidence MUST NOT be averaged into a
generic numeric score. The Mandatory decision MUST use the confidence of every
required link, not merely copy source-extraction confidence.

Provenance types are separate:

- `SourceExtractionProvenance` records source framework, benchmark identity and
  version, source and block hashes, pages, parser version, extraction method, and
  extraction timestamp.
- `CatalogObjectProvenance` records catalog authority, catalog and object
  versions, creation method, rationale sources, lifecycle changes, and
  supersession lineage. Reusable catalog objects MUST NOT claim CIS fields or
  pages as their origin.
- `MappingEvidenceProvenance` records source fields used, evidence-reference IDs,
  deterministic rule or analyst method, rule version, ontology version,
  mapping timestamp, and superseded mapping lineage.
- `ReviewProvenance` records reviewer identity, review authority, review
  timestamp, disposition, comments, and the reviewed object revision.
- `DecisionProvenance` records evaluated source, mapping, boundary-evaluation,
  rule, catalog, and ontology versions; decision scope; decision timestamp;
  reviewer approval where applicable; and superseded decision lineage.

Evidence categories are:

- `source_control_evidence`;
- `curated_security_evidence`;
- `external_reference`;
- `analyst_inference`;
- `test_evidence`; and
- `review_evidence`.

Every evidence item MUST contain `evidence_type`, `source`, `locator`,
`assertion`, `collection_method`, `confidence`, and a timestamp where the source
or collection event is time-dependent. Evidence excerpts MUST remain bounded and
attributable. A mapping without at least one permitted evidence item is invalid.
Candidate Mandatory additionally requires source-control evidence for the
enforced behavior; curated or external evidence alone is insufficient.

## 14. Object relationships

| From | Relationship | To | Cardinality |
|---|---|---|---|
| Source Recommendation | is source of | Mitigation Mapping | one-to-many |
| Mitigation Mapping | references | Security Capability | many-to-one |
| Mitigation Mapping | references | BoundaryDefinition | many-to-one |
| Mitigation Mapping | optionally references | BoundarySetDefinition | many-to-zero-or-one |
| Mitigation Mapping | optionally references | Threat Scenario | many-to-zero-or-one |
| Mitigation Mapping | corroborates with | Attack Technique | many-to-many |
| Mitigation Mapping | references | Attack Path | many-to-one |
| Security Capability | is realized by | BoundaryDefinition | many-to-many |
| BoundaryDefinition | is exposed in | Threat Scenario | many-to-many |
| Threat Scenario | involves | Attack Technique | many-to-many |
| Attack Technique | participates in | Attack Path | many-to-many |
| Attack Path | produces | Security Outcome | many-to-many |
| Threat Scenario | contextualizes | Risk | one-to-many |
| BoundarySetDefinition | implements | BoundaryDefinition | many-to-one |
| BoundaryEvaluation | evaluates | BoundaryDefinition | many-to-one |
| BoundaryEvaluation | optionally applies | BoundarySetDefinition | many-to-zero-or-one |
| Mitigation Mapping | supports | Mandatory Decision | many mappings into one decision revision |

The canonical relationship graph is therefore:

```text
SourceRecommendation → MitigationMapping
MitigationMapping → Capability
MitigationMapping → BoundaryDefinition
MitigationMapping → BoundarySetDefinition
MitigationMapping → ThreatScenario
MitigationMapping → AttackTechnique
MitigationMapping → AttackPath
```

Direct SourceRecommendation-to-Capability and SourceRecommendation-to-AttackPath
edges are derived projections only. They MUST NOT be authoritative or carry
independent evidence, confidence, or lifecycle state.

Prohibited relationships and dependencies:

- A Mandatory Decision MUST NOT define a source fact, capability, threat,
  technique, path, or outcome.
- An external technique mapping MUST NOT create or overwrite source evidence.
- Coverage aggregates MUST NOT feed back into individual candidacy merely to
  achieve a count.
- A capability MUST NOT depend on a product-specific boundary instance for its
  definition.
- A mapping MUST NOT infer its own evidence from its resulting decision.
- Circular derivations—such as Candidate Mandatory creating a boundary that is
  then used to justify the same Candidate Mandatory decision—are prohibited.

## 15. Stable identifier conventions

Identifiers MUST match these exact regular-expression grammars:

- `CAP-[0-9]{2,3}` — capability;
- `BND-[A-Z0-9]+(?:-[A-Z0-9]+)*` — BoundaryDefinition;
- `BS-[A-Z0-9]+(?:-[A-Z0-9]+)*` — BoundarySetDefinition;
- `BEV-[A-Z0-9]+(?:-[A-Z0-9]+)*` — BoundaryEvaluation;
- `TS-[0-9]{3,}` — ThreatScenario;
- `TEC-[0-9]{3,}` — internal AttackTechnique;
- `AP-[0-9]{3,}` — AttackPath;
- `OUT-[0-9]{3,}` — SecurityOutcome;
- `RISK-[0-9]{3,}` — qualitative Risk record;
- `MAP-[0-9]{3,}` — MitigationMapping; and
- `MD-[0-9]{3,}` — versioned MandatoryDecision.

Identifiers are immutable and MUST NOT be reused. Names MAY change. Deprecated
objects retain their IDs and point to successors.

`CAP-01` through `CAP-10` are immutable active identifiers and MUST be preserved.
New capability IDs use the same two-or-three-digit grammar.

Alphabetic tokens MUST be normalized to uppercase before validation. IDs MUST
not contain whitespace, underscores, punctuation other than the prescribed
hyphens, or locale-dependent characters. The designated catalog authority owns
allocation for `CAP`, `BND`, `BS`, `TS`, `TEC`, `AP`, and `OUT`. The evaluation
authority owns `BEV`; the mapping authority owns `MAP`; the decision authority
owns `RISK` and `MD`. Each ID is unique within its prefix namespace across all
catalog versions and environments.

On collision, allocation MUST fail; an implementation MUST NOT silently append,
renumber, or reuse a token. The authority must allocate a new ID and record the
rejected collision. Environment-local objects MUST include their environment or
context in provenance, not by changing identifier grammar.

IDs embedded in exports SHOULD be accompanied by catalog version so that their
meaning is reproducible.

## 16. Versioning and lifecycle

The knowledge system MUST version:

- the overall model/ontology;
- each catalog;
- deterministic rule sets; and
- individual mapping and decision revisions.

Object status is `draft`, `active`, `deprecated`, or `superseded`.

Backward-compatible changes include typo corrections that do not alter
semantics, additive optional metadata, new objects with new IDs, and additional
external mappings. Breaking changes include changed object meaning, changed
required fields, incompatible cardinality, removal or reuse of an ID, changed
boundary completeness semantics, and rule changes that alter prior mappings or
decisions.

Breaking changes require a model version change, migration notes, deterministic
re-evaluation of affected controls, and retention of old mapping lineage.
Catalog-only additions require a catalog version change. Mappings MUST record
the versions under which they were produced.

Active catalogs and rules SHOULD be reviewed at least annually and when a
material benchmark, product security model, or external framework version
changes. Deprecated objects remain readable for historical exports.

New mappings, BoundaryEvaluations, risks, and decisions MUST reference active
catalog objects. Deprecated or superseded objects MAY be referenced only when
`historical_evaluation_mode = true` and the provenance records the historical
catalog versions. A new mapping that references such an object outside that mode
is invalid. A decision encountering the reference MUST become Review Required
until the mapping is migrated to active targets.

## 17. Coverage semantics

Coverage is a set of explicit relationships and gaps, not a simplistic risk
percentage. Preventive coverage state for each applicable path and evaluated
boundary MUST be exactly one of:

- `no_effective_mitigation`: no applicable High-confidence mapping with
  `standalone_primary_boundary`/primary or
  `boundary_set_core_member`/complementary semantics is mapped;
- `complete_standalone_primary`: an applicable High-confidence standalone
  primary fully enforces the evaluated boundary;
- `complete_complementary_core_set`: all required High-confidence core effects
  and prerequisites are present and selected alternatives are resolved;
- `supporting_only`: only supporting-strength or supporting-boundary-role
  mappings are present;
- `detection_only`: only detect or investigate mappings are present; or
- `incomplete_boundary`: some primary/core mitigation exists, but a required
  effect, prerequisite, alternative, applicability decision, or accepted
  compensation is missing.

Only `no_effective_mitigation` and `incomplete_boundary` are preventive coverage
gaps. `complete_complementary_core_set` is effective mitigation even though no
single control has `mitigation_strength = primary`. `supporting_only` and
`detection_only` are explicitly non-preventive coverage states and MUST be
reported separately, not mislabeled as complete prevention.

Reports MUST additionally identify missing prerequisites, unrepresented
capabilities, threat scenarios with detection but no prevention/restriction,
preventive controls without detection/investigation coverage, unresolved
applicability, and residual path statements after partial mitigation.

The number of controls is not equivalent to attack-path coverage. Ten duplicate
settings may cover one sub-boundary, while two complementary controls may close
an entire boundary. Coverage MUST therefore aggregate distinct effects, roles,
stages, applicability, and residual path—not row counts.

## 18. Windows Server reference example

The following text is invented and does not reproduce a CIS recommendation.

**Source Recommendation**

> SR-EXAMPLE-001 — Require directory clients to authenticate LDAP messages with
> integrity protection. Description: the directory channel rejects unsigned
> authentication exchanges. Rationale: unsigned exchanges can be intercepted
> and relayed by a network-positioned attacker. Remediation and audit evidence
> identify the same enforceable setting. Applicability covers directory-connected
> servers.

**Knowledge chain**

1. The recommendation supports **CAP-01 Identity and authentication
   protection** because it protects identity validation, and **CAP-08
   Cryptographic and transport protection** because it enforces message
   integrity.
2. It enforces the signing sub-boundary of
   BoundaryDefinition `BND-DIRECTORY-LDAP-CHANNEL` through BoundarySetDefinition
   `BS-DIRECTORY-LDAP-SECURITY`. A benchmark BoundaryEvaluation records the
   applicable profile, selected signing and sealing members, and completeness.
3. Threat scenario `TS-EXAMPLE-001` states that an attacker with a network
   interception position relays an unsigned directory authentication exchange
   to act with the victim's privileges.
4. Internal technique `TEC-EXAMPLE-001` is adversary-in-the-middle credential
   relay. An optional external MITRE mapping may be attached, but does not define
   the scenario or path.
5. The scenario participates in **AP-001 Credential relay and authentication
   interception**.
6. Outcomes include unauthorized directory access and possible privilege
   escalation.
7. The atomic mapping has `boundary_role = boundary_set_core_member`,
   `mitigation_role = prevent`, and `mitigation_strength = complementary` at the
   authentication stage. LDAP channel encryption/sealing protects a distinct
   required sub-boundary, so signing alone does not complete the minimum set.
8. If signing is omitted, an integrity-unprotected relay path remains even when
   encryption/sealing protects confidentiality. The other member cannot provide
   message-authenticity enforcement and therefore cannot compensate.
9. With formal eligibility, attributable evidence, resolved applicability, High
   confidence in every required dimension, a complete BoundaryEvaluation, and
   no exclusions, the control may be proposed as **Candidate Mandatory**. Human
   approval is still required for Definitive Mandatory.

A firewall log filename or successful-connection logging setting does not
enforce the firewall traffic boundary; it is fine-tuning or detection-only. A
malware scan schedule determines when supplemental scanning occurs but does not
provide the active real-time or behavior-prevention sub-boundary. Both may map
to supporting monitoring or operational knowledge where evidence supports it,
but neither receives the same Mandatory conclusion.

## 19. Validation rules

Implementations MUST enforce these executable invariants. “Failure outcome” is
normative.

| Invariant | Required fields | Predicate and success condition | Failure outcome |
|---|---|---|---|
| Active boundary | MandatoryDecision mapping IDs; each mapping's `boundary_definition_id`; catalog lifecycle status | Every Candidate mapping target exists and has `status = active`; its BoundaryEvaluation references the same active boundary | Candidate becomes Review Required; nonexistent target also makes the mapping invalid |
| Reliable attack path | Candidate mapping IDs; AttackPath status; ThreatScenario IDs/status; all confidence dimensions | At least one atomic mapping references an active path with at least one active scenario, `mitigation_strength` primary/complementary, eligible `boundary_role`, and High confidence in every required dimension | Review Required with attack-path-mapping reason |
| Attributable evidence | Mapping evidence-reference IDs; typed evidence fields | At least one evidence item has all required evidence fields and at least one is `source_control_evidence` supporting the enforced behavior | Mapping rejected as invalid |
| No audit/reference activation | Evidence types; mapping method trace; permitted behavioral source fields | Removing references, citations, and audit-command evidence leaves the deterministic mapping predicate true | Mapping rejected; affected Candidate becomes Review Required |
| Eligible boundary role | `boundary_role`; `mitigation_strength` | Candidate uses `standalone_primary_boundary` with primary strength, `boundary_set_core_member` with complementary strength, or `prerequisite` with primary/complementary strength | Review Required |
| Duplicate effect | Source scope, boundary/effect/scope, overlap classification, selected alternative | No two mappings are both claimed as the unique primary for identical boundary, sub-boundary, effect, and applicability; one is selected or classified duplicate/alternative | Review Required for unresolved controls; duplicate primary claim invalid |
| Applicability | decision scope, applicability mode, deployment state | Combination appears in the section 11 validity table; environment Mandatory has deployed state | Invalid combination is rejected; unresolved/unknown environment decision becomes Review Required |
| Complete boundary | BoundaryEvaluation, required effects/prerequisites, alternatives, compensation evaluations, confidence | Standalone primary is complete, or every required set effect/prerequisite is satisfied by selected active High-confidence mappings or accepted full/conditional compensation | `incomplete_boundary` coverage gap and Review Required for affected Candidate |
| Compensation | CompensatingControlEvaluation required fields/status | Equivalence is full, or conditional with every condition satisfied and authorized acceptance; supporting controls are never full equivalence | Compensation rejected; residual path remains open |
| Catalog lifecycle | target IDs/status, historical mode, catalog versions | All new references are active, or deprecated/superseded references occur only in explicit historical mode | New object invalid; decision becomes Review Required until migrated |
| AttackPath validity | path status, ordered stages, active scenario IDs | Every active path has at least one active ThreatScenario; draft technique-only path is not used by Candidate | Active object invalid or Candidate mapping rejected |
| Attack stage | mapping attack stage; path ordered stages | Mapping stage is exactly one stage declared by the referenced path | Mapping rejected |
| Source identity | framework, benchmark identity/version, profile, control ID | Composite identity is complete and unique within the evaluated dataset | Source object invalid; mappings cannot be created |
| Decision provenance | decision and evaluated object/rule/catalog versions | All evaluated mapping, BoundaryEvaluation, rule, catalog, and ontology revisions are recorded | Decision invalid and cannot be published |
| Coverage distinction | coverage state and BoundaryEvaluation facts | Exactly one section 17 state is emitted; no-effective and incomplete are distinct; complete complementary set is effective | Coverage output invalid |

The current catalog implements active ThreatScenario objects and requires every
active AttackPath to resolve active scenario and outcome references. Catalog
validation blocks unresolved or inactive relationships.

## 20. Non-goals

This document and phase do not define or implement:

- graph database selection or a graph database model;
- a PostgreSQL schema;
- a REST API;
- a user interface;
- a generic numeric risk score;
- automatic Definitive Mandatory decisions;
- full MITRE ATT&CK ingestion;
- ISO 27001, NIS2, NIST CSF, or CIS Controls mappings;
- customer-specific applicability;
- customer-specific risk acceptance; or
- AI-generated source facts.

## 21. Future extensions

Controlled future extensions may include:

- an AI analyst that proposes versioned mappings with evidence;
- an independent AI reviewer that cannot approve its own proposal;
- a human adjudication workflow and Definitive Mandatory approval record;
- versioned external-framework mappings;
- customer-context overlays that leave global knowledge unchanged;
- compensating-control and alternative-boundary evaluation;
- residual-risk scoring after qualitative semantics are stable;
- cross-benchmark control-equivalence mappings;
- knowledge-graph persistence after the ontology is validated;
- a read/query API; and
- visualization of boundaries, paths, mitigations, and residual exposure.

AI-produced content MUST be marked as inferred, cite permitted source evidence,
carry confidence, and remain subject to deterministic validation and human
authority.

## Implementation-readiness checklist

- [x] Define the fact/mapping/inference/decision separation.
- [x] Preserve `CAP-01`–`CAP-10` and define exact identifier grammars.
- [x] Separate BoundaryDefinition, BoundarySetDefinition, and BoundaryEvaluation.
- [x] Define atomic MitigationMapping and the three independent role dimensions.
- [x] Define applicability, deployment state, decision scope, and confidence
      thresholds.
- [x] Define typed evidence, provenance types, lifecycle-reference rules, and
      executable invariant outcomes.
- [x] Define first-class Pydantic models for Boundary, Boundary Set, Threat
      Scenario, Attack Technique, Security Outcome, Risk Explanation, Mapping
      Provenance, BoundaryEvaluation, CompensatingControlEvaluation, and
      Mandatory Decision revision.
- [x] Assign active lifecycle status and catalog versions to current capability
      and attack-path objects.
- [x] Give each current `BS-*` object an explicit related `BND-*` boundary and
      migrate it to a BoundarySetDefinition.
- [x] Define at least one active ThreatScenario for every active attack path,
      including AP-007; techniques remain optional enrichments.
- [x] Scope Source Recommendation identity beyond bare `control_id`.
- [x] Implement typed evidence and the five provenance schemas.
- [ ] Encode the normative High-confidence Candidate matrix.
- [ ] Version deterministic mapping rules and ontology output.
- [x] Implement all six normative coverage states.
- [x] Add schema validation for implemented catalog and mapping invariants.
- [x] Define migration and compatibility fixtures before changing exports.

## Open design decisions

1. Whether composite security objectives require a separate composition object.
   Until resolved, each BoundarySetDefinition MUST reference exactly one
   BoundaryDefinition; composite behavior is expressed through related
   boundaries, not a many-to-many implementation edge.
2. The minimum granularity for threat scenarios and the criteria for path
   variants versus new AP identifiers.
   Until resolved, section 9 split criteria are normative and ambiguous scope
   forces draft status or Review Required.
3. The formal expression language for applicability and compensating-control
   conditions. Until selected, conditions MUST be structured named predicates,
   not executable free text; unresolvable predicates produce Review Required.
4. Detailed type-specific criteria for Medium and Low confidence. High is fully
   normative for Candidate decisions; Medium/Low remain descriptive and cannot
   satisfy Candidate eligibility.
5. How analyst disagreement is represented beyond separate ReviewProvenance
   records. Until resolved, disagreement prevents High final-decision confidence.
6. How Definitive Mandatory approval expiry and re-review are triggered by
   source, catalog, rule, or ontology changes.
   Until resolved, any changed referenced revision invalidates approval and
   requires re-review.
7. How residual paths are represented as structured steps without prematurely introducing numeric
   risk scoring.
   Until resolved, a bounded attributable narrative is required and must name
   the remaining entry condition, open step, and outcome.

## Current implementation and remaining migration boundary

The runtime now implements versioned catalog objects, active scenarios and
paths, atomic mitigation mappings, typed evidence and provenance, composite
source identity, separate `BND-*` and `BS-*` objects, benchmark-scoped boundary
evaluation, structured validation findings, and the six qualitative coverage
states. Backward-compatible flattened fields remain on `MandatoryAssessment`
and legacy exports.

The production Mandatory classifier has deliberately not been replaced. The
normative path runs only in advisory shadow mode, and incomplete applicability,
knowledge, confidence, alternatives, or compensation remains Review Required.
Any classifier cutover requires a separate reviewed change with decision parity
and explicit adjudication of every difference. AI-based authority, persistence,
APIs, UIs, graph storage, and customer-specific overlays remain outside v1.

## Review-resolution table

| Finding | Resolved section | Resolution summary | Remaining open question |
|---:|---|---|---|
| 1 | 6, 11, 12, 19 | Separated `boundary_role`, `mitigation_role`, and `mitigation_strength`; Candidate rules reference each correctly. | None. |
| 2 | 9, 14 | Removed mapping IDs from AttackPath and made inverse relationships derived from atomic mappings. | Shape of any future generic curated-mitigation catalog is intentionally deferred; it cannot be a source mapping. |
| 3 | 6, 15 | Defined BoundaryDefinition, BoundarySetDefinition, and BoundaryEvaluation with normative ownership and IDs. | Composite boundary composition remains constrained to one boundary per set until a separate composition concept is approved. |
| 4 | 12, 13, 19 | Defined High-confidence thresholds for every Candidate dependency and exact failure outcome. | Detailed Medium/Low criteria remain open but cannot qualify a Candidate. |
| 5 | 11, 12, 19 | Separated applicability mode, deployment state, and decision scope with a valid-combination table. | Formal condition-expression syntax remains open; unresolved predicates force review. |
| 6 | 17, 19 | Replaced no-primary gap semantics with six mutually exclusive coverage states; complete complementary sets are effective. | None. |
| 7 | 11 | Made MitigationMapping atomic with singular semantic targets and tightly limited list fields. | None. |
| 8 | 14 | Made MitigationMapping the authoritative reified relationship; direct edges are projections only. | None. |
| 9 | 15 | Defined exact regex grammars, preserved CAP-01–CAP-10, and specified normalization, authority, uniqueness, and collision handling. | None. |
| 10 | 13 | Defined five distinct provenance types and prohibited false CIS provenance on reusable catalog objects. | None. |
| 11 | 8, 9, 19 | Required every active path to reference an active scenario; technique-only paths are draft and Candidate-ineligible. | Scenario granularity remains governed by section 9 split rules pending further catalog experience. |
| 12 | 3, 10 | Split AttackPath-to-Outcome from contextual Risk derivation; generic Mandatory decisions need no customer Risk object. | Structured residual-risk scoring remains out of scope. |
| 13 | 6, 11, 19 | Added CompensatingControlEvaluation and strict equivalence acceptance rules. | Condition-expression syntax remains open; free text cannot establish equivalence. |
| 14 | 19 | Replaced qualitative invariants with required fields, predicates, success conditions, and failure outcomes. | None for Candidate validation; schemas still need implementation. |
| 15 | 13, 19 | Added typed evidence categories and mandatory evidence-item fields. | None. |
| 16 | 16, 19 | Restricted new references to active objects and confined obsolete references to explicit historical mode. | Approval expiry timing remains open; any referenced revision change currently forces re-review. |

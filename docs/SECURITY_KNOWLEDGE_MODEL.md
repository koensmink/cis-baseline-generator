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

The current implementation begins with CIS Windows Server recommendations. The
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
Security Outcome / Risk
    ↓
Mitigation Mapping
    ↓
Mandatory Decision
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

A Security Boundary is a concrete enforcement surface at which access,
execution, information flow, privilege, or security state is controlled. A
boundary may be enforced by one standalone control or by a minimum effective set
of complementary controls.

Examples include SMB session security, LDAP channel security, NTLM session
security, a host firewall, WinRM, RDP, a malware-protection stack, and a
privileged-execution boundary.

A boundary object MUST define:

- `boundary_id`;
- `name` and `description`;
- `technology_scope`;
- `applicability` and applicability mode;
- `required_sub_boundaries`;
- `minimum_effective_control_set`;
- `optional_supporting_controls`;
- `completeness_rules`;
- `compensating_control_rules`; and
- `related_capability_ids`.

`BND-*` identifies the enforcement surface. `BS-*` identifies a boundary-set
definition or deployment-specific minimum effective set. A boundary MAY have
more than one valid boundary set when alternative implementations exist.

Boundary-set roles are:

- **standalone primary boundary:** independently enforces the relevant boundary;
- **boundary-set core member:** enforces a distinct required sub-boundary;
- **prerequisite:** must exist for the boundary or a core member to function;
- **supporting hardening:** reduces exposure but does not complete the boundary;
- **fine-tuning:** adjusts parameters of an already established boundary;
- **detection-only:** observes events without enforcing the preventive boundary;
- **information-hiding:** changes exposed information or presentation without
  materially enforcing access;
- **operational:** affects administration, lifecycle, or usability without
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
- `evidence`; and
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
- `primary_mitigation_mapping_ids`;
- `complementary_mitigation_mapping_ids`;
- `residual_path_when_partially_mitigated`; and
- `confidence`.

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

An outcome object SHOULD define an immutable ID, name, description, affected
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

## 11. Mitigation Mapping

A Mitigation Mapping is the evidence-bearing relationship between a source
control and reusable security knowledge. It MUST define:

- `mapping_id` and `control_id` with full source scope;
- `capability_id`;
- `boundary_id` and, where applicable, `boundary_set_id`;
- `threat_scenario_ids`;
- `technique_ids`;
- `attack_path_ids`;
- `mitigation_role`;
- `mitigation_strength`;
- `attack_stage`;
- `enforced_sub_boundary`;
- `attack_path_if_omitted`;
- `compensating_controls` or an explicit none-known assertion;
- `non_compensability_reason`;
- `evidence`;
- `confidence`; and
- `applicability_mode` and applicability expression.

Mitigation roles are `prevent`, `restrict`, `isolate`, `protect`, `detect`,
`investigate`, and `recover`. Mitigation strengths are `primary`,
`complementary`, and `supporting`.

Applicability modes are:

- `universal` — applies throughout the declared benchmark scope;
- `mandatory_when_deployed` — applies whenever the identified technology or
  role is deployed; and
- `unresolved` — available evidence does not establish applicability.

Title matching alone is insufficient. A mapping MUST use a recognized boundary
or corroborating behavioral evidence from description, rationale, impact,
remediation, or another permitted source fact. References and audit commands
MUST NOT independently create a mapping. One mapping SHOULD express one coherent
control–capability–path–stage assertion; multiple assertions require multiple
mapping objects.

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
- at least one reliable Threat Scenario or Attack Path;
- a primary, complementary-core, or prerequisite mitigation role;
- a concrete attack path left open when the control is omitted;
- a boundary-level non-compensability explanation;
- resolved applicability;
- sufficient mapping and decision confidence; and
- no blocking exclusion.

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

The allowed values are `High`, `Medium`, and `Low`. Each type SHOULD define
type-specific criteria. Confidence MUST NOT be averaged into a generic numeric
score. The Mandatory decision MUST use the confidence of its required links,
not merely copy source-extraction confidence.

Every inferred object or mapping MUST retain:

- source fields used;
- source page range;
- source-document and block hashes where available;
- mapping method (`deterministic_rule`, `analyst`, or a future explicitly named
  method);
- rule identifier and version;
- ontology/model version;
- reviewer identity when reviewed;
- review timestamp; and
- lineage to any superseded mapping.

Evidence excerpts MUST remain bounded and attributable. A mapping without
evidence is invalid.

## 14. Object relationships

| From | Relationship | To | Cardinality |
|---|---|---|---|
| Source Recommendation | provides evidence for | Security Capability | many-to-many |
| Security Capability | is realized by | Security Boundary | many-to-many |
| Security Boundary | is exposed in | Threat Scenario | many-to-many |
| Threat Scenario | involves | Attack Technique | many-to-many |
| Attack Technique | participates in | Attack Path | many-to-many |
| Attack Path | produces | Security Outcome | many-to-many |
| Threat Scenario | contextualizes | Risk | one-to-many |
| Source Recommendation | participates in | Boundary Set | many-to-many |
| Boundary Set | implements | Security Boundary | many-to-one or many-to-many for composite boundaries |
| Source Recommendation | mitigates through mapping | Attack Path | many-to-many |
| Boundary Set | mitigates | Attack Path | many-to-many |
| Mitigation Mapping | supports | Mandatory Decision | many-to-many evidence into one decision revision |

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

New catalog identifiers SHOULD use:

- `CAP-###` — capability;
- `BND-<DOMAIN>-<NAME>` — security boundary;
- `BS-<DOMAIN>-<NAME>` — boundary-set definition;
- `TS-###` — threat scenario;
- `TEC-###` — internal attack technique;
- `AP-###` — attack path;
- `OUT-###` — security outcome;
- `RISK-###` — qualitative risk record;
- `MAP-###` — mitigation mapping; and
- `MD-###` — versioned Mandatory decision.

Identifiers are immutable and MUST NOT be reused. Names MAY change. Deprecated
objects retain their IDs and point to successors.

There is a current convention conflict: the active capability catalog uses
`CAP-01` through `CAP-10`, while the general convention above specifies
`CAP-###`. Existing capability IDs are already stable and MUST NOT be silently
renumbered. They are grandfathered until an explicit compatibility decision is
made. New implementation work must either formally adopt variable-width
`CAP-[0-9]{2,3}` identifiers or publish a versioned migration with aliases; this
document recommends preserving `CAP-01`–`CAP-10` and permitting two or three
digits.

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

## 17. Coverage semantics

Coverage is a set of explicit relationships and gaps, not a simplistic risk
percentage. Reports SHOULD distinguish:

- attack paths with no mitigation mapping;
- attack paths with no primary mitigation;
- incomplete boundary sets;
- missing prerequisites;
- capabilities not represented by applicable controls;
- threat scenarios with detection but no prevention or restriction;
- preventive controls without detection or investigation coverage;
- unresolved applicability; and
- residual attack-path statements after partial mitigation.

**No coverage** means no applicable reliable mitigation is mapped to the object.
**Incomplete coverage** means some relevant mitigation exists but a required
boundary effect, prerequisite, stage, or applicability decision is missing.
**Supporting-only coverage** means mapped controls reduce exposure without
closing the primary path.

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
   `BND-DIRECTORY-LDAP-CHANNEL`, represented in the current implementation by
   `BS-LDAP-SECURITY`.
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
7. The mapping role is `prevent` at the authentication stage. Its strength is
   `complementary` because LDAP channel encryption/sealing protects a distinct
   required sub-boundary and signing alone does not complete the minimum set.
8. If signing is omitted, an integrity-unprotected relay path remains even when
   encryption/sealing protects confidentiality. The other member cannot provide
   message-authenticity enforcement and therefore cannot compensate.
9. With formal eligibility, sufficient evidence, resolved applicability, High
   mapping confidence, a complete boundary set, and no exclusions, the control
   may be proposed as **Candidate Mandatory**. Human approval is still required
   for Definitive Mandatory.

A firewall log filename or successful-connection logging setting does not
enforce the firewall traffic boundary; it is fine-tuning or detection-only. A
malware scan schedule determines when supplemental scanning occurs but does not
provide the active real-time or behavior-prevention sub-boundary. Both may map
to supporting monitoring or operational knowledge where evidence supports it,
but neither receives the same Mandatory conclusion.

## 19. Validation rules

Implementations MUST enforce machine-testable invariants including:

1. Candidate Mandatory MUST reference an active boundary.
2. Candidate Mandatory MUST have at least one reliable attack-path mapping.
3. Candidate Mandatory MUST have a primary, complementary-core, or prerequisite
   boundary role.
4. Every Mitigation Mapping MUST contain attributable evidence.
5. No criterion or mapping may be created solely from references, citations, or
   audit commands.
6. `unresolved` applicability cannot produce an unconditional Candidate or
   Definitive Mandatory decision.
7. Duplicate controls cannot both be primary for the same boundary,
   sub-boundary, effect, and applicability scope.
8. Every active Attack Path MUST reference at least one Threat Scenario or
   internal/external Attack Technique.
9. Coverage output MUST distinguish no coverage from incomplete coverage.
10. Mapping targets MUST exist and be active in the declared catalog version.
11. A mapping's attack stage MUST occur in the referenced path's ordered stages.
12. A supporting-only mapping MUST NOT satisfy Candidate Mandatory attack-path
    evidence.
13. Source recommendation identity MUST include benchmark scope; duplicate bare
    control IDs across benchmarks MUST NOT collide.
14. A decision revision MUST cite the mapping and rule versions it evaluated.

Current implementation conflict: AP-007 has no MITRE technique ID and the model
does not yet implement Threat Scenario objects. It therefore cannot currently
satisfy invariant 8 without adding an internal technique or threat scenario.
This is a migration requirement, not grounds for inventing a source fact.

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

- [ ] Approve the fact/mapping/inference/decision separation.
- [ ] Resolve the `CAP-01` versus `CAP-###` identifier convention without silent
      renumbering.
- [ ] Define first-class Pydantic models for Boundary, Boundary Set, Threat
      Scenario, Attack Technique, Security Outcome, Risk Explanation, Mapping
      Provenance, and Mandatory Decision revision.
- [ ] Assign active lifecycle status and catalog versions to current capability
      and attack-path objects.
- [ ] Give each current `BS-*` object an explicit related `BND-*` boundary.
- [ ] Define threat scenarios or internal techniques for every active attack
      path, including AP-007.
- [ ] Scope Source Recommendation identity beyond bare `control_id`.
- [ ] Define evidence references as structured field/page/hash objects.
- [ ] Define type-specific High, Medium, and Low confidence rules.
- [ ] Version deterministic mapping rules and ontology output.
- [ ] Implement no-coverage, incomplete, and supporting-only coverage states.
- [ ] Add schema validation for all invariants in section 19.
- [ ] Define migration and compatibility fixtures before changing exports.

## Open design decisions

1. Whether new capability IDs use two or three digits, and how aliases are
   represented if three-digit IDs are adopted.
2. Whether `BND-*` represents a generic boundary type, a deployment-specific
   boundary instance, or both through separate type/instance objects.
3. Whether a boundary set may implement multiple composite boundaries directly
   or must use an explicit composition object.
4. The minimum granularity for threat scenarios and the criteria for path
   variants versus new AP identifiers.
5. Whether internal techniques are mandatory when a suitable external technique
   exists; external IDs alone must still remain non-authoritative enrichment.
6. The formal expression language for applicability and compensating-control
   conditions.
7. Type-specific confidence criteria and how analyst disagreement is retained.
8. Whether mitigation mappings are atomic per capability/path pair or can group
   several paths when role, stage, evidence, and rationale are identical.
9. How Definitive Mandatory approval expiry and re-review are triggered by
   source, catalog, rule, or ontology changes.
10. How residual paths are represented without prematurely introducing numeric
    risk scoring.

## Migration impact on the current `security_knowledge` module

The present module is a valid Phase 1 implementation subset, but it does not yet
implement the full authoritative model:

- `SecurityCapability` currently has only ID, name, and description; it lacks
  objective, examples, exclusions, lifecycle, and catalog version.
- `AttackPath` currently has stages, assets, outcomes as text, and optional MITRE
  IDs, but lacks entry/intermediate conditions, goals, linked threat scenarios,
  internal techniques, boundaries, mitigation links, residual path, lifecycle,
  and independent confidence.
- `ControlAttackPathMapping` lacks mapping ID, source scope, boundary ID, threat
  and technique links, omitted path, compensating controls, non-compensability,
  applicability, method, rule version, ontology version, and review lineage.
- Boundary definitions currently live in the Mandatory module as `BS-*`
  structures. Boundary and boundary-set semantics are combined, and there are no
  first-class `BND-*` objects.
- Threat Scenario, internal Attack Technique, Security Outcome, qualitative Risk,
  and versioned Mandatory Decision are not first-class models.
- Current enrichment stores flattened mapping aggregates directly on
  `MandatoryAssessment`. Those fields should remain backward compatible while
  canonical mapping objects become the source of aggregate exports.
- Current confidence may inherit assessment confidence or become High from
  boundary recognition and evidence count. It is not yet independently derived
  for every semantic layer.
- Current source lookup is keyed by bare `control_id`; canonical identity must be
  benchmark-scoped before multi-source ingestion is safe.
- Current coverage marks a boundary/path incomplete when any mapped assessment
  is Review Required. It does not yet evaluate explicit prerequisites, required
  effects, selected alternatives, or residual paths.
- The current `boundary_set_role` export uses `standalone` and `core member`,
  while the relationship model uses the fuller normative role names. A migration
  must define one canonical enum and backward-compatible serialization.
- The current `attack_path_if_omitted` field is a narrative on boundary
  membership, not a structured residual attack-path reference.

Migration MUST be additive first: introduce versioned canonical objects and
links, populate them from existing deterministic rules, preserve current export
columns, compare old and new decisions, and only then deprecate flattened or
ambiguous fields.

## Recommended next implementation phase

The next phase should implement the minimum ontology foundation, not storage or
AI integration:

1. Add versioned Pydantic schemas for Boundary, Boundary Set, Threat Scenario,
   Attack Technique, Security Outcome, Mapping Provenance, and decision revision.
2. Convert the eight current Windows Server boundary families into catalog data
   with separate `BND-*` and `BS-*` identities.
3. Define at least one threat scenario and one internal or external technique for
   every current attack path; resolve AP-007 first.
4. Replace bare control-ID joins with benchmark-scoped source identity.
5. Produce atomic, versioned mitigation mappings while retaining the existing
   `MandatoryAssessment` aggregate fields and CSV columns.
6. Implement the validation invariants and richer qualitative coverage states.
7. Run a decision-parity migration against the current Windows Server fixture
   and require explicit review for every changed Candidate Mandatory result.

AI analyst, independent reviewer, persistence, APIs, and customer overlays
should follow only after this deterministic ontology foundation and its
migration behavior are stable.

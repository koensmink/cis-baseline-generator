# Security Knowledge Catalog

## Purpose and ownership

The Security Knowledge Catalog is the reusable, source-independent knowledge layer of the Security Knowledge Engine. Parser output remains source evidence. The catalog describes defensive capabilities, enforcement boundaries, adversarial situations, adversary behavior, attack paths, and technical outcomes. Explicit mappings connect source recommendations to that knowledge. A Mandatory classification is a derived decision; it is not a catalog object and the catalog does not alter the current classifier.

The catalog starts with surfaces needed by the Windows Server assessment, but its concepts apply to Microsoft baselines, Linux, macOS, cloud, containers, and vulnerability information. Generic catalog objects MUST NOT contain CIS recommendation IDs or copied benchmark text.

Object ownership is deliberately separated:

| Object | Owns | Does not own |
|---|---|---|
| Capability | Technology-independent defensive ability and objective | Product settings or control IDs |
| Boundary definition | Protected enforcement surface and required effects | Benchmark profile or deployment state |
| Boundary-set definition | Generic minimum-effective combination | Selected controls in an assessment |
| Threat scenario | Concrete actor position, weakness, action, objective, and impact | Mandatory status |
| Attack technique | Reusable adversary behavior and optional external equivalence | Attack-path sequence |
| Attack path | Ordered route from entry conditions to outcomes | Source-control mitigation mappings |
| Security outcome | Generic technical consequence | Customer likelihood or numeric risk |
| Migration entry | Explicit resolution from a legacy Phase-1 boundary-set ID | Silent semantic reinterpretation |

## Stable identifiers and lifecycle

The allocation authority is the security-knowledge governance process. `CAP-01` through `CAP-10` are immutable active identifiers. New identifiers use `BND-<DOMAIN>-<TOKEN>`, `BS-<DOMAIN>-<TOKEN>`, `TS-###`, `TEC-###`, `AP-###`, and `OUT-###`. Identifiers are uppercase, unique within their object type, never reused, and never changed when a display name changes. Collisions block catalog construction.

Objects have `draft`, `active`, `deprecated`, or `superseded` lifecycle state. Active objects may reference only active objects. Deprecation preserves historical meaning. A semantic split retains the former object as deprecated or superseded and names explicit successors. New mappings and evaluations use active objects only.

Catalog provenance records the allocation authority, curation method, catalog version, reviewer, and review date. Threat scenarios additionally contain curated evidence. Catalog provenance must not claim that reusable objects originate from CIS fields.

## Current catalog

The capability catalog contains the immutable `CAP-01` through `CAP-10` set: identity and authentication protection, credential protection, privileged execution control, network boundary protection, secure remote management, application and code execution control, malware prevention and response, cryptographic and transport protection, security monitoring and investigation, and data protection. Each object states included and excluded security effects and technology-independent examples.

The active boundary catalog contains host firewall, SMB session, LDAP channel, NTLM session, WinRM, RDP, endpoint malware protection, privileged credentials, application control, script control, generic transport cryptography, storage encryption, security audit, password-authentication strength, external identity authentication, weak/plaintext authentication, privileged-role activation, multifactor authentication, phishing-resistant authentication, authentication strength, session assurance, session binding, and managed-device trust surfaces. Nineteen boundary sets define their minimum-effective combinations. Profile and deployment choices remain evaluation context, not generic catalog identity.

Catalog version 1.1.0 adds the final six reusable identity surfaces in that
list. Their boundary sets express semantic completeness without source control
identity. They reuse `CAP-01`, `CAP-02`, and, where cryptographic or context
binding is material, `CAP-08`; no new capability was needed.

The additional authentication threat chains cover password guessing,
authentication through an unapproved external identity trust, and capture or
replay of plaintext credentials. Source recommendations mapped to these
concepts remain incomplete until their distinct required effects,
applicability, and non-compensability are supported by attributable evidence;
the presence of a generic catalog concept alone does not qualify a Candidate
Mandatory decision.

Privileged-role activation is distinct from operating-system elevation: it
governs the transition from eligible or dormant authority to active
administrative authority. Its reusable threat chain covers activation without
independent approval and applies to cloud, identity, infrastructure, and other
just-in-time privilege systems.

The initial threat catalog contains eighteen concrete scenarios, including inbound-service exposure, administrative lateral movement, SMB and LDAP relay, NTLM downgrade and weak session protection, remote-management interception and abuse, credential extraction, weak elevation consent, protection disablement, malware evasion, untrusted execution, audit suppression and evidence loss, plaintext credential interception, and unencrypted storage exposure. Every active scenario contains actor position, preconditions, assets, weakness, action, objective, immediate outcome, technical impact, boundary and technique references, High confidence, evidence, and provenance.

Seventeen internal techniques include the existing authentication, remote-service, execution, impairment, audit, and encryption behaviors plus credential phishing, MFA bypass, session-token replay, and device-trust bypass. Twenty-one active attack paths include reviewed `AP-001` through `AP-010` and generic paths for application execution, transport and storage exposure, password and external-identity authentication, privileged activation, password-only compromise, phishing-resistant bypass, session replay, stale-session abuse, and untrusted-device access. `AP-010` has explicit threat and outcome references and is not an empty placeholder. Fourteen generic outcomes cover unauthorized access and authentication, credential theft, privilege escalation, lateral movement, code and malware execution, protection impairment, confidentiality, integrity, availability, broad administrative compromise, forensic evidence loss, and unauthorized data access.

## Relationship and external-mapping policy

Normative relationships flow from capability to boundary definition; boundary definition to boundary-set definition; threat scenario to boundary and technique; and attack path to threat scenario, technique, and security outcome. Reverse collections are derived queries. Source recommendations connect only through mitigation or migration mapping objects. Attack paths never store source mapping IDs, preventing circular reasoning.

MITRE ATT&CK and CWE identifiers are optional external mappings on internal techniques. They are enrichments, not internal identity. A MITRE technique is not an attack path. A CWE identifies a weakness class, not a threat scenario or path. Only a semantically equivalent or explicitly related behavior is mapped, with mapping type, confidence, URL or reference, and provenance. The catalog performs no automatic external ingestion and defines no CVE object.

## Legacy migration

The migration map explicitly resolves every current Phase-1 Windows boundary-set family: domain, private, and public host firewall; SMB; LDAP; NTLM; WinRM; RDP; malware protection; and privileged credentials. Each entry states the normative set, boundary definition, capabilities, paths, migration status, and semantic notes. The domain firewall legacy identity resolves to the generic host-firewall boundary while retaining profile as evaluation context. Missing resolution emits a structured finding and requires review; the adapter never invents a mapping.

The compatibility adapter enriches existing Candidate Mandatory assessments with normative boundary, boundary-set, threat-scenario, path, capability, and outcome identifiers. It is projection-only. It does not feed catalog conclusions back into Mandatory classification in this phase, so the authoritative Windows result remains 27 Candidate Mandatory, 5 Review Required, and 275 Regular Control.

## Validation and deterministic export

Catalog construction rejects duplicate IDs. `validate()` reports structured errors for invalid syntax, unresolved or inactive references, missing provenance, incomplete active threats, boundary sets without active boundaries or completeness definitions, malformed MITRE/CWE mappings, active paths without active threats or outcomes, an empty active `AP-010`, and incomplete legacy migration coverage. The authoritative catalog must have zero errors. Warnings are permitted only when documented with an owner and consequence; version 1.0.0 has none.

`to_deterministic_json()` includes metadata, all objects and relationships, lifecycle, external mappings, provenance, migration entries, and a validation summary. It uses canonical key ordering, stable catalog tuple order, compact separators, UTF-8 text, and one trailing newline. Unchanged input therefore produces byte-stable `security-knowledge-catalog.json`; `write_catalog_json()` writes that representation.

Normative coverage distinguishes no effective mitigation, complete standalone-primary coverage, complete complementary-core coverage, supporting-only coverage, detection-only coverage, and incomplete boundaries. It also reports represented capabilities, threats, and outcomes and unresolved migrations. A complete complementary set is effective coverage. Counts of controls are not a risk percentage, and this phase defines no numeric risk score.

## Extension and governance

An extension proposal MUST define semantics, exclusions, identifier allocation, lifecycle, provenance, relationships, evidence, confidence, validation impact, and migration impact. A security architect reviews boundaries and capabilities; a threat-model reviewer reviews scenarios, techniques, paths, and outcomes; a maintainer verifies deterministic serialization and compatibility. Changes that remove required fields, reinterpret active IDs, or alter relationship meaning require a major catalog version and explicit migrations. Additive active objects and defensible external mappings are minor changes; editorial clarifications are patches.

Current limitations are intentional: the catalog has no persistence layer, API, UI, graph database, AI-generated mapping, CVE ingestion, full CWE or ATT&CK ingestion, customer context, numeric risk score, or classifier cutover. Coverage reflects known mappings, not customer residual risk. The next phase should add atomic source-to-catalog mitigation mappings and benchmark-scoped boundary evaluations under the authoritative knowledge model, followed by reviewed migration—not an implicit classifier switch.

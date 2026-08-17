# Benchmark Family Adapters

## Purpose

Benchmark-family adapters isolate source-product terminology, applicability,
and boundary-candidate recognition from the generic Security Knowledge Model.
They do not make Mandatory decisions. Generic orchestration still requires
formal eligibility, a complete boundary, a concrete attack path,
non-compensability, resolved applicability, evidence, and confidence.

## Supported families

- `microsoft-windows-server`
- `microsoft-365-foundations`

Parser identity detection uses benchmark-title evidence from source metadata.
It does not infer family from filenames. Missing evidence produces `unknown`;
conflicting supported titles produce `ambiguous`.

## Adapter selection

The registry evaluates every adapter and accepts a selection only when exactly
one adapter supports the record. Zero matches emit
`BENCHMARK_FAMILY_UNSUPPORTED`; multiple matches emit
`BENCHMARK_FAMILY_AMBIGUOUS`. Neither condition silently falls back to Windows.

Each adapter provides deterministic operations for applicability
normalization, semantic domains, boundary candidates, security-role context,
and family-specific evidence. Boundary candidates require behavior evidence
from description, rationale, or remediation. Titles, audit commands, and
references cannot activate mappings by themselves.

## Microsoft 365 applicability

The Microsoft 365 adapter separates license and deployment facts:

- license: `E3`, `E5`, `E3_or_E5`, or `unknown`;
- deployment: `tenant_wide`, `feature_specific`, `service_specific`,
  `conditional`, or `unknown`;
- status: `applicable`, `mandatory_when_feature_deployed`, `not_applicable`, or
  `unresolved`.

License eligibility never proves that an optional feature is deployed.
Conditional source evidence therefore remains conditional at benchmark scope.

Recognized semantic domains include authentication, privileged-role
activation, application registration and consent, external collaboration,
mail security, auditing, data protection, service-principal authorization, and
meeting or cross-tenant collaboration. Domain recognition only narrows
possible catalog concepts; it never creates a Candidate Mandatory result.

## Windows isolation

Windows Server keeps its SMB, LDAP, NTLM, WinRM, RDP, Windows Firewall,
Defender, UAC, host-profile, and host applicability rules. Generic
orchestration invokes those rules only for the Windows Server adapter. An
explicit Microsoft 365 control cannot receive a Windows host boundary merely
because similar words appear in its title.

## Adding a family

1. Add evidence-based parser identity detection.
2. Implement the adapter interface without changing generic Mandatory rules.
3. Define typed applicability that separates product entitlement from deployed
   state.
4. Reuse catalog capabilities, boundaries, scenarios, paths, and outcomes
   before adding objects.
5. Add only reusable missing concepts with provenance and complete reference
   validation.
6. Require behavior evidence and deterministic ordering.
7. Add invented tests for selection, ambiguity, applicability, title/audit
   isolation, missing knowledge, and product-boundary isolation.
8. Run existing family regressions before enabling advisory shadow evaluation.

Capabilities, boundary semantics, attack techniques, attack paths, outcomes,
confidence rules, completeness states, and Mandatory decision principles must
remain generic. Product names, source vocabulary, license syntax, deployment
conditions, and deterministic source-to-catalog predicates may remain in the
family adapter.

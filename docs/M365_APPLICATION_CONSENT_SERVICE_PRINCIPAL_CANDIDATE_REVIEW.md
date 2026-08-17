# Microsoft 365 application and workload identity Candidate review

## Advisory shadow result

The deterministic six-control synthetic slice produces four Candidate Mandatory, one Review Required, and one Regular Control. Relative to the pre-slice catalog, the four complete controls move from unresolved catalog coverage to Candidate, the incomplete consent concept remains Review Required, and title-only content remains Regular. This is advisory shadow output; there is no classifier cutover.

## New Candidate explanations

| Synthetic control | Boundary completeness | Attack path closed | Applicability | Non-compensability |
|---|---|---|---|---|
| 10.1 | Completes restricted creation, constrained registrar authority, and accountable ownership. | `AP-023`: an unauthorized principal can otherwise register a persistent attacker-controlled application identity. | Tenant application-registration scope; E3/E5 benchmark applicability is resolved and no optional deployment condition is asserted. | Inventory, ownership reports, or registration logs cannot prevent unauthorized identity creation. |
| 10.2 | Completes untrusted-consent restriction, independent privileged-grant approval, and permission-scope constraint. | `AP-024`: a malicious application can otherwise acquire delegated or administrative privilege through an unsafe grant. | Tenant application-consent scope; E3/E5 benchmark applicability is resolved and no optional deployment condition is asserted. | Publisher display, consent reporting, or post-grant monitoring cannot stop the permission grant. |
| 10.3 | Completes least-privilege authority, explicit authorization, and enforced review/revocation lifecycle. | `AP-025`: a controlled service principal can otherwise abuse excessive, implicit, or stale authority. | Tenant service-principal scope; E3/E5 benchmark applicability is resolved and no optional deployment condition is asserted. | Authentication hardening and activity logging do not remove excessive authorization. |
| 10.4 | Completes issuer, subject, and audience constraints on the same workload trust relationship. | `AP-026`: a token from an unintended workload context can otherwise authenticate as the trusted workload. | Tenant workload-identity scope; E3/E5 benchmark applicability is resolved and no optional deployment condition is asserted. | Secret rotation, token logging, or transport security cannot repair an overbroad claim trust decision. |

## Review and Regular results

Synthetic control 10.5 proves approval of a privileged permission grant but does not prove restriction of untrusted consent or a constrained permission scope. Its boundary remains incomplete and its residual consent-privilege path remains open, so it is Review Required.

Synthetic control 10.6 places all product terms in the title while its behavioral fields establish no security effect. It receives no semantic mapping and remains Regular Control. Audit and reference fields likewise cannot activate these mappings.

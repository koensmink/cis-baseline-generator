# Microsoft 365 Application Consent and Service-Principal Knowledge

## Scope

This advisory extension covers application registration, user and administrator consent, privileged application permissions, service-principal authorization, and workload identity trust. It does not change the production classifier or authorize cutover.

## Reuse and missing boundaries

The slice reuses identity and authentication protection (`CAP-01`), credential protection (`CAP-02`), privileged execution control (`CAP-03`), cryptographic and transport protection (`CAP-08`), and the existing unauthorized-authentication, privilege-escalation, confidentiality-loss, and administrative-compromise outcomes.

Four generic enforcement boundaries were genuinely missing:

- `BND-IDENTITY-APPLICATION-REGISTRATION-AUTHORIZATION` requires restricted application identity creation, constrained registrar authority, and accountable ownership.
- `BND-IDENTITY-APPLICATION-CONSENT-AUTHORIZATION` requires restriction of untrusted consent, independent approval of privileged grants, and constrained permission scope.
- `BND-IDENTITY-SERVICE-PRINCIPAL-AUTHORIZATION` requires least-privilege non-human authority, explicit authorization, and an enforced authorization lifecycle.
- `BND-IDENTITY-WORKLOAD-IDENTITY-TRUST` requires issuer, subject, and audience constraints on federated workload trust.

Registration does not grant resource authority, consent does not prove continuing least privilege, service-principal authorization does not prove authentic workload provenance, and workload federation does not constrain what an authenticated principal may do. The boundaries therefore remain separate.

## Deterministic evidence and applicability

The Microsoft 365 family adapter maps behavior from description, rationale, remediation, and applicability. A title, audit procedure, reference, inventory statement, report, or product term cannot activate a mapping. Each required effect must have explicit semantic evidence; partial concepts remain Review Required.

License entitlement does not prove deployment. Optional or conditionally deployed application or workload features retain conditional applicability and remain Review Required at benchmark scope until applicability is resolved.

## Candidate reasoning

A complete application-registration boundary closes unauthorized creation of persistent application identities. A complete consent boundary closes acquisition of delegated or application authority through untrusted or overbroad grants. A complete service-principal boundary closes abuse of excessive, implicit, or stale non-human authority. A complete workload-trust boundary closes impersonation through issuer, subject, or audience mismatch.

For each boundary, monitoring and inventory are compensating evidence only: they do not prevent the relevant creation, grant, authorization, or authentication decision. Advisory Candidate status additionally requires resolved applicability, High confidence, an eligible boundary role, a complete boundary evaluation, a concrete active attack path, and non-compensability. Any missing required effect leaves the corresponding path open and produces Review Required.

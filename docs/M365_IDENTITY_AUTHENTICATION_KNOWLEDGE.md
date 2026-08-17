# Microsoft 365 Identity and Authentication Knowledge

## Scope

This extension covers multifactor authentication, phishing-resistant authentication, authentication strength, session assurance and freshness, authentication transfer/session binding, and managed-device authentication trust. It is advisory and does not change the production classifier or authorize cutover.

## Reusable boundaries

- `BND-IDENTITY-MULTIFACTOR-AUTHENTICATION` requires an additional independent factor, an enforced access scope, and bypass resistance.
- `BND-IDENTITY-PHISHING-RESISTANT-AUTHENTICATION` requires cryptographic verifier binding, origin or channel binding, and replay/proxy resistance.
- `BND-IDENTITY-AUTHENTICATION-STRENGTH` requires a selected minimum strength, an enforced scope, and rejection of weaker methods.
- `BND-IDENTITY-SESSION-ASSURANCE` requires reauthentication freshness and protected session continuation. Risk- or event-driven revalidation is an enhancement, not a universal prerequisite.
- `BND-IDENTITY-AUTHENTICATION-SESSION-BINDING` requires transfer prohibition, binding to the originating context, and token-replay resistance.
- `BND-IDENTITY-MANAGED-DEVICE-TRUST` requires trusted device identity, a device-state assertion, and enforcement at authentication.

MFA proves that more than one independent authentication factor is enforced. It does not prove phishing resistance: a factor may still be captured, proxied, replayed, or fatigue-abused. Phishing-resistant authentication therefore has a distinct cryptographic and origin-binding boundary. Authentication strength is the separate policy surface that admits or rejects methods according to a defined strength.

Session assurance asks whether authenticated access remains fresh and protected after time, risk, or context changes. Session binding asks whether authenticated state can move to another device, browser, channel, or session. Device trust asks whether identity and current device state are enforced at authentication. Enrollment or compliance evaluation alone does not enforce that decision.

## Applicability

License entitlement and deployment are separate. E3 or E5 can make a feature available but cannot prove that device management, compliance policy, hybrid identity, or a dependent access policy is deployed. Tenant-wide, feature-specific, service-specific, managed-device-dependent, and conditional deployment remain distinct. Unresolved managed-device trust is Review Required.

## Completeness and Mandatory reasoning

Each set is complete only when every required effect has behavioral evidence. A title, audit instruction, reference, capability report, registration state, product name, or license statement cannot fill a missing effect. One recommendation may prove several effects, while complementary recommendations may jointly complete one surface.

An advisory Candidate also needs an active capability and boundary, a primary, complementary-core, or prerequisite role, High confidence, a concrete active attack path, non-compensability, resolved benchmark applicability, and no blocking finding. Product terminology such as “MFA,” “phishing-resistant,” or “authentication strength” is therefore insufficient by itself.

The generic paths cover password-only compromise, phishing-resistant bypass, session replay or authentication transfer, stale-session abuse, and untrusted-device access. Omitting a required core effect leaves its path open; monitoring, method preference, or licensing cannot compensate for missing preventive enforcement.

## Known Microsoft 365 gaps

The three previously classification-relevant gaps represented authentication freshness, authentication transfer/session binding, and managed-device trust. They now resolve by behavioral semantics to generic catalog objects. Their CIS identifiers are validation observations only, never catalog identities or mapping keys. Resolution does not guarantee Candidate status: freshness may belong to an incomplete assurance set, and device trust remains Review Required while its deployment dependency is conditional.

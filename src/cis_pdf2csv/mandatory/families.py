from __future__ import annotations

FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("MC-01 Accounts and authentication", ("account", "authentication", "password", "logon", "credential")),
    ("MC-02 Privileged access and rights", ("privilege", "administrator", "elevat", "user right")),
    ("MC-03 Network access and protocol security", ("network", "firewall", "remote", "protocol", "smb", "winrm", "ssh")),
    ("MC-04 Logging and auditing", ("audit", "logging", "event log")),
    ("MC-05 Attack surface and functionality restriction", ("attack surface", "disable", "functionality", "legacy")),
    ("MC-06 Execution and content security", ("execution", "macro", "script", "extension", "application control", "allowlist")),
    ("MC-07 Cryptography and transport security", ("encrypt", "signing", "tls", "transport", "secure channel")),
    ("MC-08 Security configuration and policy enforcement", ("policy", "security configuration", "enforcement", "malware", "antivirus", "isolation", "sandbox")),
)


def classify_family(text: str) -> str:
    lowered = text.lower()
    scored = [(sum(term in lowered for term in terms), family) for family, terms in FAMILIES]
    score, family = max(scored, key=lambda item: item[0])
    return family if score else "MC-08 Security configuration and policy enforcement"

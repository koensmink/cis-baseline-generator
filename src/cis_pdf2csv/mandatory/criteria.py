from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Criterion:
    code: str
    label: str
    patterns: tuple[str, ...]


CRITERIA: tuple[Criterion, ...] = (
    Criterion("MC-CRIT-001", "Unsafe or legacy protocols or mechanisms", (r"\b(?:unsafe|insecure|deprecated|obsolete|legacy) (?:protocol|mechanism|authentication|credential)", r"\bntlmv?1\b", r"\bsmbv?1\b", r"\bminimum (?:supported )?smb version\b", r"\btelnet\b", r"\blan manager hash")),
    Criterion("MC-CRIT-002", "Fundamental authentication or access restrictions", (r"\b(?:require|enforce|prompt for) (?:user )?authentication\b", r"\b(?:disable|disallow|refuse|block) (?:basic|digest|lm|ntlm|weak|legacy) (?:authentication|credentials?)", r"\brestrict(?:ing)? anonymous access\b", r"\bnetwork level authentication\b", r"\bidentity validation\b", r"\bdeny logon\b", r"\bmulti-factor authentication\b")),
    Criterion("MC-CRIT-003", "Privileged-access protection", (r"\bprivileged access\b", r"\badministrator account", r"\badmin approval\b")),
    Criterion("MC-CRIT-004", "Credential protection", (r"\bcredential guard\b", r"\bcredential protection\b", r"\bpassword hash", r"\bsecret storage\b")),
    Criterion("MC-CRIT-005", "Elevated execution", (r"\belevated execution\b", r"\belevation of privilege\b", r"\brun as administrator\b", r"\bprivilege elevation\b")),
    Criterion("MC-CRIT-006", "Direct remote access", (r"\b(?:allow|block|deny|disable|disallow|restrict) (?:direct )?(?:remote access|remote desktop|remote logon|remote shell)", r"\b(?:remote|rdp) (?:user )?authentication\b", r"\bsecurity layer for (?:remote|rdp)", r"\b(?:winrm|remote desktop).{0,80}(?:credentials?|authentication|unencrypted|security layer)", r"\b(?:drive|clipboard|device|resource|webauthn|com port|lpt port) redirection\b")),
    Criterion("MC-CRIT-007", "Direct code, macro, script or extension execution", (r"\bmacro execution\b", r"\bscript execution\b", r"\bcode execution\b", r"\bbrowser extension\b", r"\bpowershell execution\b")),
    Criterion("MC-CRIT-008", "Fundamental network protection", (r"\bnetwork protection\b", r"\bnetwork boundary\b", r"\binbound connection", r"\bnetwork access control\b")),
    Criterion("MC-CRIT-009", "Firewalling", (r"\bfirewall\b",)),
    Criterion("MC-CRIT-010", "Transport protection", (r"\btransport protection\b", r"\btls\b", r"\bsecure channel\b", r"\bhttps\b")),
    Criterion("MC-CRIT-011", "Signing", (r"\bdigital(?:ly)? sign", r"\bmessage signing\b", r"\bcode signing\b", r"\b(?:smb|ldap) signing\b")),
    Criterion("MC-CRIT-012", "Encryption", (r"\b(?:require|enforce|enable|mandate).{0,30}\bencryption\b", r"\b(?:disable|disallow|refuse|block) (?:unencrypted|plaintext|cleartext)", r"\bdo not (?:send|store|transmit).{0,50}(?:unencrypted|plaintext|cleartext)", r"\breversible encryption.{0,40}disabled\b", r"\b(?:ldap|ntlm).{0,50}(?:encryption|sealing|128-bit)", r"\b(?:rdp|remote desktop).{0,50}(?:high encryption|encryption level)", r"\bbitlocker.{0,80}(?:require|enable|enforce)")),
    Criterion("MC-CRIT-013", "Isolation or sandboxing", (r"\bisolation\b", r"\bsandbox", r"\bapplication guard\b")),
    Criterion("MC-CRIT-014", "Application control", (r"\bapplication control\b", r"\ballowlist", r"\bapp locker\b", r"\bapplocker\b")),
    Criterion("MC-CRIT-015", "Essential security audit or logging", (r"\b(?:essential|sole|required) (?:source of )?(?:security )?(?:audit|logging)", r"\b(?:essential|sole) (?:audit|log) source\b")),
    Criterion("MC-CRIT-016", "Fundamental malware protection", (r"\bfundamental (?:malware|antivirus) protection\b", r"\breal-time (?:malware )?protection\b", r"\bbehavior monitoring\b", r"\bedr (?:in )?block mode\b", r"\bnetwork protection.{0,40}block mode\b", r"\b(?:disable|turn off) (?:microsoft )?defender\b", r"\bturn off real-time protection.{0,30}disabled\b")),
)

AUDIT_TITLE = re.compile(r"\baudit\b", re.IGNORECASE)
AUDIT_HIGH_IMPACT = re.compile(
    r"\b(?:privilege escalation|credential theft|malware execution|security state|system integrity|account compromise)\b",
    re.IGNORECASE,
)


def match_criteria(text: str, title: str | None = None) -> list[str]:
    """Return stable criterion codes in registry order."""
    lowered = text.lower()
    if title and AUDIT_TITLE.search(title):
        essential = any(
            re.search(pattern, lowered)
            for pattern in next(item for item in CRITERIA if item.code == "MC-CRIT-015").patterns
        )
        return ["MC-CRIT-015"] if essential and AUDIT_HIGH_IMPACT.search(lowered) else []
    return [
        criterion.code
        for criterion in CRITERIA
        if any(re.search(pattern, lowered) for pattern in criterion.patterns)
    ]


def criterion_label(code: str) -> str:
    return next((item.label for item in CRITERIA if item.code == code), code)

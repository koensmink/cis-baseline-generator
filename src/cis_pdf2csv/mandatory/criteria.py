from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Criterion:
    code: str
    label: str
    patterns: tuple[str, ...]


CRITERIA: tuple[Criterion, ...] = (
    Criterion("MC-CRIT-001", "Unsafe or legacy protocols or mechanisms", (r"\blegacy\b", r"\binsecure protocol\b", r"\bntlmv1\b", r"\bsmbv1\b", r"\btelnet\b")),
    Criterion("MC-CRIT-002", "Fundamental authentication or access restrictions", (r"\bauthentication\b", r"\baccess restriction", r"\bdeny logon\b", r"\bmulti-factor\b")),
    Criterion("MC-CRIT-003", "Privileged-access protection", (r"\bprivileged access\b", r"\badministrator account", r"\badmin approval\b")),
    Criterion("MC-CRIT-004", "Credential protection", (r"\bcredential guard\b", r"\bcredential protection\b", r"\bpassword hash", r"\bsecret storage\b")),
    Criterion("MC-CRIT-005", "Elevated execution", (r"\belevated execution\b", r"\belevation of privilege\b", r"\brun as administrator\b", r"\bprivilege elevation\b")),
    Criterion("MC-CRIT-006", "Direct remote access", (r"\bremote desktop\b", r"\bdirect remote access\b", r"\bremote logon\b", r"\bwinrm\b", r"\bssh access\b")),
    Criterion("MC-CRIT-007", "Direct code, macro, script or extension execution", (r"\bmacro execution\b", r"\bscript execution\b", r"\bcode execution\b", r"\bbrowser extension\b", r"\bpowershell execution\b")),
    Criterion("MC-CRIT-008", "Fundamental network protection", (r"\bnetwork protection\b", r"\bnetwork boundary\b", r"\binbound connection", r"\bnetwork access control\b")),
    Criterion("MC-CRIT-009", "Firewalling", (r"\bfirewall\b",)),
    Criterion("MC-CRIT-010", "Transport protection", (r"\btransport protection\b", r"\btls\b", r"\bsecure channel\b", r"\bhttps\b")),
    Criterion("MC-CRIT-011", "Signing", (r"\bdigital signing\b", r"\bmessage signing\b", r"\bcode signing\b", r"\bsmb signing\b")),
    Criterion("MC-CRIT-012", "Encryption", (r"\bencryption\b", r"\bencrypt\b", r"\bbitlocker\b")),
    Criterion("MC-CRIT-013", "Isolation or sandboxing", (r"\bisolation\b", r"\bsandbox", r"\bapplication guard\b")),
    Criterion("MC-CRIT-014", "Application control", (r"\bapplication control\b", r"\ballowlist", r"\bapp locker\b", r"\bapplocker\b")),
    Criterion("MC-CRIT-015", "Essential security audit or logging", (r"\bsecurity audit", r"\baudit log", r"\bsecurity logging\b", r"\blogon audit\b")),
    Criterion("MC-CRIT-016", "Fundamental malware protection", (r"\bmalware protection\b", r"\bantivirus\b", r"\banti-malware\b", r"\breal-time protection\b")),
)


def match_criteria(text: str) -> list[str]:
    """Return stable criterion codes in registry order."""
    lowered = text.lower()
    return [
        criterion.code
        for criterion in CRITERIA
        if any(re.search(pattern, lowered) for pattern in criterion.patterns)
    ]


def criterion_label(code: str) -> str:
    return next((item.label for item in CRITERIA if item.code == code), code)

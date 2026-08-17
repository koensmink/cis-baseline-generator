from __future__ import annotations

import re
from dataclasses import dataclass

from cis_pdf2csv.schema import ControlRecord
from cis_pdf2csv.security_knowledge.adapters import BenchmarkFamily, select_adapter
from cis_pdf2csv.source_identity import source_identity_for_control

from .schema import ApplicabilityMode, OverlapType


@dataclass(frozen=True)
class BoundaryDefinition:
    boundary_set_id: str
    boundary_set_name: str
    required_effects: frozenset[str]
    applicability_mode: ApplicabilityMode = "universal"


@dataclass(frozen=True)
class BoundaryMembership:
    definition: BoundaryDefinition
    effect: str
    enforced_sub_boundary: str
    attack_path_if_omitted: str
    standalone: bool = False
    required_effect: str | None = None


@dataclass(frozen=True)
class BoundaryContext:
    membership: BoundaryMembership | None
    related_core_member_ids: tuple[str, ...] = ()
    complete: bool = False
    overlap_type: OverlapType = "none"
    missing_required_effects: tuple[str, ...] = ()


FIREWALL_REQUIRED = frozenset({"firewall_enabled", "default_inbound_block"})
SMB_REQUIRED = frozenset({"minimum_version", "signing_required"})
LDAP_REQUIRED = frozenset({"ldap_signing", "ldap_encryption"})
NTLM_REQUIRED = frozenset({"legacy_auth_refused", "session_security"})
WINRM_REQUIRED = frozenset({"basic_auth_disabled", "unencrypted_disabled"})
RDP_REQUIRED = frozenset({"nla_required", "tls_layer", "high_encryption"})
MALWARE_REQUIRED = frozenset({"real_time", "behavior_monitoring", "network_block"})


def _contains(text: str, *terms: str) -> bool:
    return any(term in text for term in terms)


def _membership(
    definition: BoundaryDefinition,
    effect: str,
    sub_boundary: str,
    attack_path: str,
    *,
    standalone: bool = False,
    required_effect: str | None = None,
) -> BoundaryMembership:
    return BoundaryMembership(
        definition, effect, sub_boundary, attack_path, standalone, required_effect
    )


def identify_boundary_membership(control: ControlRecord) -> BoundaryMembership | None:
    selection = select_adapter(control)
    if selection.family != BenchmarkFamily.MICROSOFT_WINDOWS_SERVER:
        return None
    title = " ".join(control.title.lower().split())
    context = " ".join(
        part
        for part in (
            title,
            (control.description or "").lower(),
            (control.rationale or "").lower(),
            (control.remediation or "").lower(),
        )
        if part
    )

    if "firewall" in title:
        profile_match = re.search(r"\b(domain|private|public)\b", title)
        profile = profile_match.group(1) if profile_match else "applicable"
        definition = BoundaryDefinition(
            f"BS-HOST-FIREWALL-{profile.upper()}",
            f"Host firewall ({profile} profile)",
            FIREWALL_REQUIRED,
        )
        if _contains(title, "firewall state", "firewall enabled"):
            return _membership(definition, "firewall_enabled", "stateful firewall enforcement", "the host accepts traffic without an active packet-filtering boundary")
        if "inbound" in title and _contains(title, "block", "blocked"):
            return _membership(definition, "default_inbound_block", "default-deny inbound policy", "unsolicited inbound traffic is permitted unless every service is separately restricted")
        return None

    smb = BoundaryDefinition("BS-SMB-SECURITY", "SMB protocol security", SMB_REQUIRED)
    if "smb" in title or "microsoft network" in title:
        if _contains(title, "minimum version", "minimum supported smb version", "smbv1", "smb 1"):
            return _membership(smb, "minimum_version", "minimum safe SMB protocol version", "a peer can negotiate an obsolete SMB protocol")
        if _contains(title, "digitally sign", "signing") and "audit" not in title:
            if _contains(title, "if server agrees", "if client agrees"):
                return None
            scope = "client" if "network client" in title else "server" if "network server" in title else "session"
            return _membership(smb, f"{scope}_signing_required", "SMB message authenticity", "an active network attacker can alter or relay unsigned SMB sessions", required_effect="signing_required")
        if "password" in title and _contains(title, "unencrypted", "plaintext"):
            return _membership(smb, "plaintext_password_disabled", "SMB credential confidentiality", "an SMB peer can receive a reusable plaintext password")
        if "insecure guest" in title and _contains(title, "disable", "disabled", "disallow"):
            return _membership(smb, "insecure_guest_disabled", "authenticated SMB sessions", "an unauthenticated guest session can reach shared resources")

    ldap = BoundaryDefinition("BS-LDAP-SECURITY", "LDAP channel security", LDAP_REQUIRED)
    if "ldap" in title:
        if "signing" in title:
            return _membership(ldap, "ldap_signing", "LDAP message authenticity", "LDAP messages can be altered or relayed in transit")
        if _contains(title, "encryption", "sealing"):
            return _membership(ldap, "ldap_encryption", "LDAP channel confidentiality", "directory credentials or queries can cross an unsealed channel")

    ntlm = BoundaryDefinition("BS-NTLM-SESSION", "NTLM authentication and session security", NTLM_REQUIRED)
    if _contains(title, "lan manager authentication level", "refuse lm", "refuse ntlm"):
        return _membership(ntlm, "legacy_auth_refused", "legacy credential refusal", "a peer can authenticate with LM or weak NTLM credentials")
    if "ntlm" in title and _contains(title, "minimum session security", "128-bit", "session encryption"):
        scope = "client" if "clients" in title else "server" if "servers" in title else "session"
        return _membership(ntlm, f"{scope}_session_security", "NTLM session integrity and encryption", "an authenticated NTLM session can negotiate weak integrity or encryption", required_effect="session_security")

    winrm = BoundaryDefinition(
        "BS-WINRM-SECURITY",
        "WinRM secure management channel",
        WINRM_REQUIRED,
        "mandatory_when_deployed",
    )
    if "winrm" in context:
        scope = "client" if "winrm client" in context else "service" if "winrm service" in context else "channel"
        if "basic authentication" in title and _contains(title, "disable", "disabled", "disallow"):
            return _membership(winrm, f"{scope}_basic_auth_disabled", "strong WinRM authentication", "a management endpoint accepts replayable Basic credentials", required_effect="basic_auth_disabled")
        if "unencrypted" in title and _contains(title, "disable", "disabled", "disallow"):
            return _membership(winrm, f"{scope}_unencrypted_disabled", "encrypted WinRM transport", "management commands and credentials can cross an unencrypted channel", required_effect="unencrypted_disabled")
        if _contains(title, "storing", "storage") and "credential" in title:
            return _membership(winrm, "credential_storage_disabled", "WinRM delegated credential protection", "reusable management credentials remain stored on the target")

    rdp = BoundaryDefinition(
        "BS-RDP-SECURITY",
        "Remote Desktop secure access",
        RDP_REQUIRED,
        "mandatory_when_deployed",
    )
    if _contains(context, "remote desktop", "rdp", "remote connections"):
        if _contains(title, "network level authentication", "nla"):
            return _membership(rdp, "nla_required", "pre-session identity validation", "an unauthenticated client reaches the interactive RDP stack")
        if _contains(title, "security layer", "ssl", "tls"):
            return _membership(rdp, "tls_layer", "authenticated RDP transport", "a remote session can negotiate a weaker security layer")
        if "encryption level" in title and _contains(context, "high", "128"):
            return _membership(rdp, "high_encryption", "RDP session confidentiality", "remote-session content can use insufficient encryption")
        if _contains(title, "remote desktop", "remote logon") and _contains(title, "allow log on", "deny log on"):
            effect = "remote_logon_allow" if "allow" in title else "remote_logon_deny"
            return _membership(rdp, effect, "RDP authorization boundary", "an unintended principal retains interactive remote-logon rights")

    malware = BoundaryDefinition(
        "BS-MALWARE-PROTECTION",
        "Active malware protection stack",
        MALWARE_REQUIRED,
        "mandatory_when_deployed",
    )
    if "real-time protection" in title and _contains(title, "during scans", "during oobe"):
        return None
    if _contains(title, "real-time protection", "real-time malware protection"):
        return _membership(malware, "real_time", "real-time file and process prevention", "malicious content can execute before a scheduled scan")
    if "behavior monitoring" in title:
        return _membership(malware, "behavior_monitoring", "behavior-based prevention", "malicious behavior not identified by static signatures can execute")
    if "network protection" in context and "block" in context:
        return _membership(malware, "network_block", "malicious-destination blocking", "a process can connect to a known malicious destination")
    if "edr" in title and "block mode" in title:
        return _membership(malware, "edr_block", "EDR post-breach blocking", "EDR detections cannot actively stop malicious artifacts")
    if _contains(title, "disable defender", "turn off defender"):
        return _membership(malware, "tamper_prevention", "continued malware protection", "a local change can disable the protection stack")

    privilege = BoundaryDefinition(
        "BS-PRIVILEGED-CREDENTIALS",
        "Privileged execution and credential protection",
        frozenset(),
    )
    standalone_effects = (
        (("secure desktop",), "secure_desktop", "trusted elevation consent", "malware can spoof or manipulate the elevation prompt"),
        (("run all administrators", "admin approval mode"), "uac_admin_approval", "mediated privileged execution", "administrative code executes without UAC mediation"),
        (("built-in administrator", "admin approval mode"), "builtin_admin_approval", "mediated built-in Administrator execution", "the built-in Administrator bypasses UAC mediation"),
        (("credential guard",), "credential_guard", "isolated credential material", "credential secrets remain accessible to the normal operating system"),
        (("lsass", "protected process"), "lsass_protection", "protected LSASS process", "a normal process can read or inject into the credential authority"),
        (("reversible encryption",), "reversible_passwords_disabled", "non-recoverable password storage", "stored passwords remain reversibly recoverable"),
        (("lan manager hash",), "lm_hashes_disabled", "removal of LM password hashes", "an attacker can crack the weak LM representation offline"),
        (("wdigest",), "wdigest_disabled", "plaintext credential storage prevention", "reusable plaintext credentials remain in LSASS memory"),
    )
    for terms, effect, sub_boundary, attack_path in standalone_effects:
        if all(term in title for term in terms):
            return _membership(privilege, effect, sub_boundary, attack_path, standalone=True)
    return None


def analyze_boundary_sets(controls: list[ControlRecord]) -> list[BoundaryContext]:
    memberships = [identify_boundary_membership(control) for control in controls]
    grouped: dict[tuple[tuple[str, str, str, str, str], str], list[int]] = {}
    for index, membership in enumerate(memberships):
        if membership:
            scope = source_identity_for_control(controls[index]).benchmark_scope()
            grouped.setdefault((scope, membership.definition.boundary_set_id), []).append(index)

    contexts: list[BoundaryContext] = []
    for index, membership in enumerate(memberships):
        if not membership:
            contexts.append(BoundaryContext(None))
            continue
        scope = source_identity_for_control(controls[index]).benchmark_scope()
        member_indices = grouped[(scope, membership.definition.boundary_set_id)]
        group_members = [
            (member_index, item)
            for member_index in member_indices
            if (item := memberships[member_index]) is not None
        ]
        effects = [item.effect for _, item in group_members]
        required_effects_present = {
            item.required_effect or item.effect
            for _, item in group_members
        }
        effect_count = effects.count(membership.effect)
        complete = not membership.definition.required_effects or membership.definition.required_effects.issubset(required_effects_present)
        overlap: OverlapType = "duplicate" if effect_count > 1 else "complementary" if len(set(effects)) > 1 else "none"
        related = tuple(
            sorted(
                controls[item].control_id
                for item, related_membership in group_members
                if item != index and related_membership.effect != membership.effect
            )
        )
        missing = tuple(sorted(membership.definition.required_effects - required_effects_present))
        contexts.append(BoundaryContext(membership, related, complete, overlap, missing))
    return contexts


def applicability_mode(
    control: ControlRecord,
    membership: BoundaryMembership | None,
) -> ApplicabilityMode:
    if membership:
        return membership.definition.applicability_mode
    title = control.title.lower()
    applicability = (control.applicability or "").lower()
    if "smart card" in title or "smart-card" in title:
        return "mandatory_when_deployed" if "smart card" in applicability else "unresolved"
    if _contains(title, "remote desktop", "rds", "winrm", "defender", "antivirus", "edr", "printer", "rpc"):
        return "mandatory_when_deployed"
    return "universal"

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass

import fitz

SECTION_HEADINGS = [
    "Profile Applicability",
    "Description",
    "Rationale",
    "Rationale Statement",
    "Impact",
    "Impact Statement",
    "Audit",
    "Audit Procedure",
    "Remediation",
    "Remediation Procedure",
    "Default Value",
    "References",
]


SECTION_CANONICAL_MAP = {
    "profile applicability": "applicability",
    "description": "description",
    "rationale": "rationale",
    "rationale statement": "rationale",
    "impact": "impact",
    "impact statement": "impact",
    "audit": "audit",
    "audit procedure": "audit",
    "remediation": "remediation",
    "remediation procedure": "remediation",
    "default value": "default_value",
    "references": "references",
}


RE_HEADER = re.compile(
    r"^(?P<id>\d+(?:\.\d+)+)\s+"
    r"(?:\((?P<profile>L1|L2|NG)\)\s+)?"
    r"(?P<title>.+?)"
    r"(?:\s+\((?P<assessment>Automated|Manual)\))?"
    r"(?:\s+\([^)]+\))*\s*$"
)


RE_BENCHMARK_META = re.compile(
    r"\bCIS\s+Microsoft\s+Windows\s+Server\s+(?P<product>\d{4}(?:\s*R2)?)(?:\s+Stand-alone)?(?:\s+Benchmark)?\b",
    re.IGNORECASE,
)

RE_M365_BENCHMARK_META = re.compile(
    r"\bCIS\s+Microsoft\s+365\s+Foundations\s+Benchmark\b",
    re.IGNORECASE,
)

RE_GENERIC_BENCHMARK_META = re.compile(
    r"\bCIS\s+(?P<name>.+?\s+Benchmark)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class BenchmarkIdentity:
    family: str
    benchmark_name: str
    finding: str | None = None


class UnsupportedBenchmarkIdentityError(ValueError):
    """Backward-compatible error for callers that imported the old parser gate."""

    def __init__(self, identity: BenchmarkIdentity) -> None:
        self.identity = identity
        super().__init__(
            f"{identity.finding or 'BENCHMARK_FAMILY_UNSUPPORTED'}: "
            "PDF benchmark identity is unsupported or ambiguous"
        )


def detect_benchmark_identity(lines: list[str]) -> BenchmarkIdentity:
    """Detect family metadata without deciding whether the document is parseable."""
    evidence = " ".join(" ".join(line.split()) for line in lines[:50])
    windows_matches = list(RE_BENCHMARK_META.finditer(evidence))
    m365_matches = list(RE_M365_BENCHMARK_META.finditer(evidence))
    if windows_matches and m365_matches:
        generic_match = RE_GENERIC_BENCHMARK_META.search(evidence)
        benchmark_name = (
            f"CIS {' '.join(generic_match.group('name').split())}"
            if generic_match
            else "Unknown CIS Benchmark"
        )
        return BenchmarkIdentity(
            family="ambiguous",
            benchmark_name=benchmark_name,
            finding="BENCHMARK_FAMILY_AMBIGUOUS",
        )
    if windows_matches:
        product = windows_matches[0].group("product")
        return BenchmarkIdentity(
            family="microsoft-windows-server",
            benchmark_name=f"CIS Microsoft Windows Server {product} Benchmark",
        )
    if m365_matches:
        return BenchmarkIdentity(
            family="microsoft-365-foundations",
            benchmark_name="CIS Microsoft 365 Foundations Benchmark",
        )
    generic_match = RE_GENERIC_BENCHMARK_META.search(evidence)
    if generic_match:
        name = " ".join(generic_match.group("name").split())
        return BenchmarkIdentity(family="unknown", benchmark_name=f"CIS {name}")
    return BenchmarkIdentity(family="unknown", benchmark_name="Unknown CIS Benchmark")


class CISStructureError(ValueError):
    """Raised when a PDF cannot be reliably recognized as a CIS benchmark."""

    def __init__(self, code: str = "CIS_STRUCTURE_NOT_DETECTED") -> None:
        self.code = code
        super().__init__(f"{code}: reliable CIS benchmark structure was not detected")


RE_VERSION_DATE = re.compile(
    r"^v(?P<version>[0-9.]+)\s*[–-]\s*(?P<date>.+)$"
)


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_text(t: str) -> str:
    return hashlib.sha256(t.encode("utf-8", errors="replace")).hexdigest()


def _normalize_text(text: str) -> str:
    text = text.replace("\u00ad", "")
    text = re.sub(r"(\w)-\n(\w)", r"\1\2", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = "\n".join([ln.rstrip() for ln in text.splitlines()])
    return text


def _normalize_heading(line: str) -> str:
    """
    Normalize heading text so variants like:
    - 'Rationale'
    - 'Rationale:'
    - 'Rationale Statement'
    all become comparable.
    """
    return line.strip().rstrip(":").strip().lower()


def _flatten_lines(lines: list[str]) -> str | None:
    """
    Join multiline section text into a single normalized line.
    This avoids visible \\n characters in CSV / Excel output.
    """
    if not lines:
        return None

    text = " ".join(lines)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _looks_like_control_start(line: str) -> bool:
    """
    Heuristic: does this line look like the start of a CIS control header?
    Example:
    18.10.15.2 Ensure 'Enumerate administrator accounts on ...
    """
    return bool(re.match(r"^\d+(?:\.\d+)+\s+", line))


def _consume_multiline_header(
    lines: list[tuple[int, str]],
    start_index: int,
) -> tuple[str, int]:
    """
    Consume one or more lines that together form a single control header.

    Returns:
        (combined_header_text, last_consumed_index)

    Logic:
    - Start from a line that looks like a control header.
    - If the line already contains (Automated) or (Manual), we assume it is complete.
    - Otherwise, append following lines until:
      - (Automated) or (Manual) appears, or
      - the next line looks like a new control start, or
      - a known body section heading starts.
    """
    _, line = lines[start_index]
    candidate = line

    if "(Automated)" in candidate or "(Manual)" in candidate:
        return candidate, start_index

    i = start_index + 1
    while i < len(lines):
        _, next_line = lines[i]
        normalized_next = _normalize_heading(next_line)

        # Stop if we appear to hit the next control
        if _looks_like_control_start(next_line):
            break

        # Stop if we hit a body heading
        if normalized_next in SECTION_CANONICAL_MAP:
            break

        candidate = f"{candidate} {next_line}".strip()

        if "(Automated)" in candidate or "(Manual)" in candidate:
            return candidate, i

        i += 1

    return candidate, i - 1 if i > start_index else start_index


def find_body_start_page(pdf_path: str) -> int:
    """
    Detect where the actual control body begins.
    We skip the TOC by searching for known section headings.
    """
    doc = fitz.open(pdf_path)

    needles = [
        "Profile Applicability",
        "Description",
        "Rationale",
        "Rationale Statement",
        "Impact",
        "Impact Statement",
        "Audit",
        "Audit Procedure",
        "Remediation",
        "Remediation Procedure",
        "Default Value",
        "References",
    ]

    for i in range(doc.page_count):
        text = _normalize_text(doc.load_page(i).get_text("text"))

        if any(n in text for n in needles):
            return i + 1

    return 1


def iter_pdf_lines(pdf_path: str, start_page: int) -> Iterator[tuple[int, str]]:
    doc = fitz.open(pdf_path)

    for i in range(start_page - 1, doc.page_count):
        page = doc.load_page(i)
        text = _normalize_text(page.get_text("text"))

        for ln in text.splitlines():
            ln = ln.strip()
            if ln:
                yield (i + 1, ln)


def extract_benchmark_meta(pdf_path: str) -> tuple[str, str, str]:
    doc = fitz.open(pdf_path)

    text = _normalize_text(doc.load_page(0).get_text("text"))
    lines = [l.strip() for l in text.splitlines() if l.strip()]

    identity = detect_benchmark_identity(lines)
    if identity.benchmark_name == "Unknown CIS Benchmark":
        raise CISStructureError()
    name = identity.benchmark_name
    version = ""
    date = ""

    for idx, ln in enumerate(lines[:50]):
        m2 = RE_VERSION_DATE.match(ln.replace("–", "-"))
        if m2:
            version = f"v{m2.group('version')}"
            date = m2.group("date")

    return name, version, date


def _split_title_applicability(raw_title: str):
    applicability = []
    title = raw_title

    while True:
        m = re.search(r"\(([^)]+only)\)", title, re.IGNORECASE)

        if not m:
            break

        applicability.append(m.group(1))
        title = title.replace(m.group(0), "").strip()

    return title.strip(), "; ".join(applicability) if applicability else None


def _profile_from_applicability(text: str | None):
    if not text:
        return "Unknown"

    t = text.lower()

    if "level 2" in t:
        return "L2"

    if "level 1" in t:
        return "L1"

    return "Unknown"


def _is_real_control(sections: dict[str, str | None]) -> bool:
    """
    Reject TOC blocks.
    Only accept if real CIS body sections exist.
    """
    if sections.get("audit") or sections.get("remediation"):
        return True

    return bool(sections.get("applicability"))


def parse_controls(pdf_path: str, profile_filter: str | None = None) -> list[dict]:
    with open(pdf_path, "rb") as f:
        pdf_hash = sha256_bytes(f.read())

    bench_name, bench_version, bench_date = extract_benchmark_meta(pdf_path)
    start_page = find_body_start_page(pdf_path)

    controls: list[dict] = []

    current: dict | None = None
    current_lines: list[str] = []
    current_end_page: int | None = None

    lines = list(iter_pdf_lines(pdf_path, start_page))
    i = 0

    while i < len(lines):
        page, line = lines[i]

        m = None
        last_header_index = i

        if _looks_like_control_start(line):
            header_candidate, last_header_index = _consume_multiline_header(lines, i)
            m = RE_HEADER.match(header_candidate)

        if m:
            # Finalize previous control
            if current:
                block_text = "\n".join(current_lines).strip()

                current["page_end"] = current_end_page or current["page_start"]
                current["block_text_sha256"] = sha256_text(block_text)

                sections = _extract_sections(block_text)

                if _is_real_control(sections):
                    current.update(sections)
                    current["profile"] = _profile_from_applicability(
                        current.get("applicability")
                    )
                    controls.append(current)

            control_id = m.group("id")
            assessment = m.group("assessment") or "Unknown"
            raw_title = m.group("title")

            title, applicability_tag = _split_title_applicability(raw_title)

            current = {
                "benchmark_name": bench_name,
                "benchmark_version": bench_version,
                "benchmark_date": bench_date,
                "control_id": control_id,
                "profile": "Unknown",
                "title": title,
                "assessment": assessment,
                "applicability": applicability_tag,
                "page_start": page,
                "page_end": page,
                "source_pdf_sha256": pdf_hash,
                "extracted_at_utc": _utc_now(),
                "parser_version": "0.4.1",
                "block_text_sha256": "",
            }

            current_lines = []
            current_end_page = lines[last_header_index][0]

            # Skip consumed header lines
            i = last_header_index + 1
            continue

        else:
            if current:
                current_lines.append(line)
                current_end_page = page

        i += 1

    # Finalize last control
    if current:
        block_text = "\n".join(current_lines).strip()

        current["page_end"] = current_end_page or current["page_start"]
        current["block_text_sha256"] = sha256_text(block_text)

        sections = _extract_sections(block_text)

        if _is_real_control(sections):
            current.update(sections)
            current["profile"] = _profile_from_applicability(
                current.get("applicability")
            )
            controls.append(current)

    if not controls:
        raise CISStructureError()

    if profile_filter:
        pf = profile_filter.upper()
        controls = [
            c for c in controls if (c.get("profile") or "").upper() == pf
        ]

    return controls


def _utc_now():
    import datetime

    return datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _extract_sections(block_text: str) -> dict[str, str | None]:
    """
    Extract CIS control sections from a control text block.

    Supports both older section names:
    - Rationale Statement
    - Impact Statement
    - Audit Procedure
    - Remediation Procedure

    and newer section names:
    - Rationale
    - Impact
    - Audit
    - Remediation
    """
    lines = [ln.strip() for ln in block_text.splitlines() if ln.strip()]

    sections_accumulator: dict[str, list[str]] = {
        "applicability": [],
        "description": [],
        "rationale": [],
        "impact": [],
        "audit": [],
        "remediation": [],
        "default_value": [],
        "references": [],
    }

    current_key = "description"

    for ln in lines:
        normalized = _normalize_heading(ln)

        if normalized in SECTION_CANONICAL_MAP:
            current_key = SECTION_CANONICAL_MAP[normalized]
            continue

        sections_accumulator[current_key].append(ln)

    return {
        "applicability": _flatten_lines(sections_accumulator["applicability"]),
        "description": _flatten_lines(sections_accumulator["description"]),
        "rationale": _flatten_lines(sections_accumulator["rationale"]),
        "impact": _flatten_lines(sections_accumulator["impact"]),
        "audit": _flatten_lines(sections_accumulator["audit"]),
        "remediation": _flatten_lines(sections_accumulator["remediation"]),
        "default_value": _flatten_lines(sections_accumulator["default_value"]),
        "references": _flatten_lines(sections_accumulator["references"]),
    }

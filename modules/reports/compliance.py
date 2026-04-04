"""
AegisAI — NIST 800-53 Rev5 Compliance Report Generator  (v2.3+)

Aggregates findings from all completed scans and produces:
  • Per-control gap analysis (which NIST controls have open findings)
  • Severity breakdown (critical / high / medium / low / info)
  • Provider breakdown (aws / azure / gcp / network / k8s / iac)
  • Overall compliance score  (0–100, weighted by severity)
  • Markdown and dict output formats

NIST 800-53 Rev5: CA-7 (Continuous Monitoring), CM-6, AU-2, RA-5.

Usage:
    from modules.reports.compliance import ComplianceReportGenerator
    generator = ComplianceReportGenerator()
    report = generator.generate(findings, metadata={"scan_count": 3})
    print(report.overall_score)
    report.to_markdown()
    report.to_dict()
"""

from __future__ import annotations

import io
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING
import xml.etree.ElementTree as ET

if TYPE_CHECKING:
    from modules.scanners.base import Finding


# Severity weights used for score calculation (higher = worse)
_SEVERITY_WEIGHT: Dict[str, int] = {
    "critical": 100,
    "high":     60,
    "medium":   30,
    "low":      10,
    "info":     2,
}

# Max possible penalty per finding tier (for score normalisation)
_MAX_PENALTY_PER_FINDING = 100


@dataclass
class ControlGap:
    """A NIST 800-53 control with one or more open findings."""
    control_id: str
    findings: List[Any] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def max_severity(self) -> str:
        order = ["critical", "high", "medium", "low", "info"]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return "info"


@dataclass
class ComplianceReport:
    """
    Immutable result of a ComplianceReportGenerator.generate() call.

    Attributes:
        overall_score       — 0-100 (100 = no findings, 0 = all critical)
        total_findings      — total number of findings across all scans
        findings_by_severity — {severity: count} dict
        findings_by_provider — {provider: count} dict
        control_gaps        — list of ControlGap (controls with open findings)
        metadata            — caller-supplied metadata dict
        generated_at        — ISO-8601 timestamp of report generation
    """
    overall_score: float
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings_by_provider: Dict[str, int]
    control_gaps: List[ControlGap]
    metadata: Dict[str, Any]
    generated_at: str

    # ── Rendering helpers ──────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "overall_score":        round(self.overall_score, 1),
            "total_findings":       self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_provider": self.findings_by_provider,
            "control_gaps": [
                {
                    "control_id":    cg.control_id,
                    "finding_count": cg.finding_count,
                    "max_severity":  cg.max_severity,
                    "findings": [
                        {
                            "resource":           f.resource,
                            "issue":              f.issue,
                            "severity":           f.severity,
                            "provider":           f.provider,
                            "remediation_hint":   f.remediation_hint,
                        }
                        for f in cg.findings
                    ],
                }
                for cg in sorted(self.control_gaps, key=lambda c: c.control_id)
            ],
            "metadata":      self.metadata,
            "generated_at":  self.generated_at,
        }

    def to_pdf_bytes(self) -> bytes:
        """Generate a PDF report using stdlib only (no reportlab/weasyprint)."""
        md = self.to_markdown()
        lines: List[str] = []
        for raw_line in md.splitlines():
            lines.extend(_wrap_text(raw_line, max_chars=90))
        return _build_pdf_bytes(lines, title="AegisAI — NIST 800-53 Rev5 Compliance Report")

    def to_docx_bytes(self) -> bytes:
        """Generate a DOCX report using stdlib only (no python-docx)."""
        md = self.to_markdown()
        paragraphs = md.splitlines()
        return _build_docx_bytes(paragraphs, title="AegisAI — NIST 800-53 Rev5 Compliance Report")

    def to_markdown(self) -> str:
        lines: List[str] = []
        lines.append("# AegisAI — NIST 800-53 Rev5 Compliance Report")
        lines.append("")
        lines.append(f"**Generated:** {self.generated_at}")
        lines.append(f"**Overall Score:** {self.overall_score:.1f} / 100")
        lines.append(f"**Total Findings:** {self.total_findings}")
        lines.append("")

        # Severity summary table
        lines.append("## Findings by Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = self.findings_by_severity.get(sev, 0)
            lines.append(f"| {sev.upper()} | {count} |")
        lines.append("")

        # Provider summary table
        if self.findings_by_provider:
            lines.append("## Findings by Provider")
            lines.append("")
            lines.append("| Provider | Count |")
            lines.append("|---|---|")
            for provider, count in sorted(self.findings_by_provider.items()):
                lines.append(f"| {provider} | {count} |")
            lines.append("")

        # Control gap analysis
        if self.control_gaps:
            lines.append("## NIST 800-53 Control Gaps")
            lines.append("")
            lines.append("Controls with one or more open findings:")
            lines.append("")
            for cg in sorted(self.control_gaps, key=lambda c: c.control_id):
                lines.append(f"### {cg.control_id}  *(max severity: {cg.max_severity.upper()}, {cg.finding_count} finding(s))*")
                for f in cg.findings:
                    hint = f" — *{f.remediation_hint}*" if f.remediation_hint else ""
                    lines.append(f"- **[{f.severity.upper()}]** `{f.resource}`: {f.issue}{hint}")
                lines.append("")
        else:
            lines.append("## NIST 800-53 Control Gaps")
            lines.append("")
            lines.append("*No control gaps detected — all findings are unmapped or scan results are empty.*")
            lines.append("")

        # Metadata footer
        if self.metadata:
            lines.append("## Scan Metadata")
            lines.append("")
            for k, v in self.metadata.items():
                lines.append(f"- **{k}**: {v}")
            lines.append("")

        return "\n".join(lines)


# ── Stdlib-only PDF / DOCX helpers ───────────────────────────────────────────


def _wrap_text(text: str, max_chars: int = 90) -> List[str]:
    """Word-wrap *text* to lines of at most *max_chars* characters."""
    words = text.split()
    lines: List[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 <= max_chars:
            current = (current + " " + word).lstrip()
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def _build_pdf_bytes(text_lines: List[str], title: str = "Aegis Compliance Report") -> bytes:
    """
    Build a minimal valid PDF 1.4 document from a list of text lines.

    Uses only Python stdlib — no reportlab, no weasyprint.
    Fonts: built-in Courier (monospace) for body, Helvetica-Bold for headers.
    """
    # ── helpers ───────────────────────────────────────────────────────────────
    objects: List[bytes] = []  # indexed 1-based
    offsets: List[int] = []

    def add_obj(content: bytes) -> int:
        objects.append(content)
        return len(objects)  # 1-based object number

    def _ps_escape(s: str) -> str:
        """Escape special PDF string characters."""
        s = s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        # Strip non-latin chars to keep PDF simple
        return s.encode("latin-1", errors="replace").decode("latin-1")

    # ── page layout constants ──────────────────────────────────────────────────
    PAGE_W, PAGE_H = 612, 792
    MARGIN_LEFT, MARGIN_TOP = 50, 742
    LINE_HEIGHT = 14
    BODY_FONT_SIZE = 10
    TITLE_FONT_SIZE = 14
    LINES_PER_PAGE = 50

    # ── split lines into pages ──────────────────────────────────────────────
    def chunk_pages(lines: List[str], per_page: int) -> List[List[str]]:
        pages = []
        for i in range(0, max(len(lines), 1), per_page):
            pages.append(lines[i : i + per_page])
        return pages

    pages_lines = chunk_pages([title, ""] + text_lines, LINES_PER_PAGE)
    num_pages = len(pages_lines)

    # ── object 1: catalog (placeholder — will be fixed up) ───────────────────
    # object 2: page tree
    # objects 3...: page + content stream pairs

    # We build objects in order, tracking byte offsets.
    buf = io.BytesIO()
    buf.write(b"%PDF-1.4\n")
    buf.write(b"%\xe2\xe3\xcf\xd3\n")  # binary comment (marks as binary PDF)

    all_obj_offsets: Dict[int, int] = {}
    obj_counter = [0]

    def begin_obj(n: int) -> None:
        all_obj_offsets[n] = buf.tell()
        buf.write(f"{n} 0 obj\n".encode())

    def end_obj() -> None:
        buf.write(b"endobj\n")

    # We'll write objects sequentially.
    # Object numbering:
    #   1 = Catalog
    #   2 = Pages
    #   3 = Font (Helvetica-Bold, titles)
    #   4 = Font (Courier, body)
    #   5..(4+num_pages) = Page objects
    #   (4+num_pages+1)..(4+2*num_pages) = Content streams

    total_objs = 4 + 2 * num_pages

    page_obj_start = 5
    content_obj_start = 5 + num_pages

    # ── Object 1: Catalog ────────────────────────────────────────────────────
    begin_obj(1)
    buf.write(b"<< /Type /Catalog /Pages 2 0 R >>\n")
    end_obj()

    # ── Object 2: Pages ──────────────────────────────────────────────────────
    kids = " ".join(f"{page_obj_start + i} 0 R" for i in range(num_pages))
    begin_obj(2)
    buf.write(f"<< /Type /Pages /Kids [{kids}] /Count {num_pages} >>\n".encode())
    end_obj()

    # ── Object 3: Helvetica-Bold font ────────────────────────────────────────
    begin_obj(3)
    buf.write(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\n")
    end_obj()

    # ── Object 4: Courier font ───────────────────────────────────────────────
    begin_obj(4)
    buf.write(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>\n")
    end_obj()

    # ── Page objects ─────────────────────────────────────────────────────────
    for i in range(num_pages):
        content_ref = content_obj_start + i
        begin_obj(page_obj_start + i)
        buf.write(
            f"<< /Type /Page /Parent 2 0 R "
            f"/MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Contents {content_ref} 0 R "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>\n".encode()
        )
        end_obj()

    # ── Content streams ───────────────────────────────────────────────────────
    for i, page_lines in enumerate(pages_lines):
        stream_parts: List[str] = ["BT"]
        y = MARGIN_TOP
        first_line = True
        for line in page_lines:
            safe = _ps_escape(line)
            # Use bold font for first line (title) and lines starting with '#'
            if first_line or line.startswith("#"):
                stream_parts.append(f"/F1 {TITLE_FONT_SIZE if first_line else BODY_FONT_SIZE} Tf")
                first_line = False
            else:
                stream_parts.append(f"/F2 {BODY_FONT_SIZE} Tf")
            stream_parts.append(f"{MARGIN_LEFT} {y} Td")
            stream_parts.append(f"({safe}) Tj")
            stream_parts.append("0 0 Td")  # reset position delta
            y -= LINE_HEIGHT
            if y < 50:
                break
        stream_parts.append("ET")
        stream_content = ("\n".join(stream_parts)).encode("latin-1")

        begin_obj(content_obj_start + i)
        buf.write(f"<< /Length {len(stream_content)} >>\n".encode())
        buf.write(b"stream\n")
        buf.write(stream_content)
        buf.write(b"\nendstream\n")
        end_obj()

    # ── Cross-reference table ─────────────────────────────────────────────────
    xref_offset = buf.tell()
    buf.write(b"xref\n")
    buf.write(f"0 {total_objs + 1}\n".encode())
    buf.write(b"0000000000 65535 f \n")
    for n in range(1, total_objs + 1):
        off = all_obj_offsets.get(n, 0)
        buf.write(f"{off:010d} 00000 n \n".encode())

    # ── Trailer ───────────────────────────────────────────────────────────────
    buf.write(b"trailer\n")
    buf.write(f"<< /Size {total_objs + 1} /Root 1 0 R >>\n".encode())
    buf.write(b"startxref\n")
    buf.write(f"{xref_offset}\n".encode())
    buf.write(b"%%EOF\n")

    return buf.getvalue()


def _build_docx_bytes(paragraphs: List[str], title: str = "Aegis Compliance Report") -> bytes:
    """
    Build a minimal valid DOCX (Office Open XML) from a list of paragraph strings.

    Uses only Python stdlib: zipfile + xml.etree.ElementTree.
    No python-docx dependency.
    """
    # ── XML namespaces ────────────────────────────────────────────────────────
    W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    RELS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
    PKG_REL_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    DOC_REL_TYPE_STYLES = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"

    # Register namespaces for clean XML output
    ET.register_namespace("w", W)

    def _w(tag: str) -> str:
        return f"{{{W}}}{tag}"

    def make_para(text: str, style: str = "Normal", bold: bool = False) -> ET.Element:
        p = ET.Element(_w("p"))
        pPr = ET.SubElement(p, _w("pPr"))
        pStyle = ET.SubElement(pPr, _w("pStyle"))
        pStyle.set(_w("val"), style)
        if text.strip():
            r = ET.SubElement(p, _w("r"))
            if bold:
                rPr = ET.SubElement(r, _w("rPr"))
                b_elem = ET.SubElement(rPr, _w("b"))
                b_elem.set(_w("val"), "true")
            t = ET.SubElement(r, _w("t"))
            t.text = text
            t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        return p

    # ── Build document.xml ────────────────────────────────────────────────────
    doc = ET.Element(_w("document"))
    body = ET.SubElement(doc, _w("body"))

    # Title paragraph
    body.append(make_para(title, style="Heading1", bold=True))

    # Content paragraphs
    for para in paragraphs:
        is_heading = para.startswith("#")
        clean = para.lstrip("# ").strip()
        style = "Heading2" if is_heading else "Normal"
        body.append(make_para(clean, style=style, bold=is_heading))

    doc_xml = b"<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\n" + ET.tostring(doc, encoding="unicode").encode("utf-8")

    # ── [Content_Types].xml ───────────────────────────────────────────────────
    content_types_xml = (
        """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"""
    ).encode("utf-8")

    # ── _rels/.rels ───────────────────────────────────────────────────────────
    pkg_rels_xml = (
        f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{RELS_NS}">
  <Relationship Id="rId1" Type="{PKG_REL_TYPE}" Target="word/document.xml"/>
</Relationships>"""
    ).encode("utf-8")

    # ── word/_rels/document.xml.rels ──────────────────────────────────────────
    doc_rels_xml = (
        f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{RELS_NS}">
  <Relationship Id="rId1" Type="{DOC_REL_TYPE_STYLES}" Target="styles.xml"/>
</Relationships>"""
    ).encode("utf-8")

    # ── word/styles.xml (minimal) ─────────────────────────────────────────────
    styles_xml = (
        """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal">
    <w:name w:val="Normal"/>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading1">
    <w:name w:val="heading 1"/>
    <w:rPr><w:b/><w:sz w:val="32"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading2">
    <w:name w:val="heading 2"/>
    <w:rPr><w:b/><w:sz w:val="26"/></w:rPr>
  </w:style>
</w:styles>"""
    ).encode("utf-8")

    # ── Pack into ZIP ─────────────────────────────────────────────────────────
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", pkg_rels_xml)
        zf.writestr("word/document.xml", doc_xml)
        zf.writestr("word/_rels/document.xml.rels", doc_rels_xml)
        zf.writestr("word/styles.xml", styles_xml)

    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────


class ComplianceReportGenerator:
    """
    Aggregates a list of Finding objects into a ComplianceReport.

    Score algorithm (NIST CA-7 continuous monitoring):
      Base score = 100
      Each finding deducts:  severity_weight / max_penalty * (100 / max(total, 1)) * dampening
      Score is clamped to [0, 100].

    A deployment with zero findings scores 100.
    A deployment with 10 critical findings scores ~0.
    """

    def generate(
        self,
        findings: List[Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ComplianceReport:
        """
        Build a ComplianceReport from a list of Finding objects.

        Args:
            findings:  list of modules.scanners.base.Finding instances
            metadata:  caller-supplied dict merged into the report

        Returns:
            ComplianceReport
        """
        generated_at = datetime.now(timezone.utc).isoformat()
        metadata = metadata or {}

        # ── Severity + provider counts ─────────────────────────────────────────
        findings_by_severity: Dict[str, int] = defaultdict(int)
        findings_by_provider: Dict[str, int] = defaultdict(int)

        for f in findings:
            sev = getattr(f, "severity", "info").lower()
            prov = getattr(f, "provider", "unknown").lower()
            findings_by_severity[sev] += 1
            findings_by_provider[prov] += 1

        # ── Control gap mapping ────────────────────────────────────────────────
        control_map: Dict[str, ControlGap] = {}
        for f in findings:
            for ctrl in getattr(f, "nist_controls", []):
                if ctrl not in control_map:
                    control_map[ctrl] = ControlGap(control_id=ctrl)
                control_map[ctrl].findings.append(f)

        # ── Score calculation ──────────────────────────────────────────────────
        total = len(findings)
        if total == 0:
            score = 100.0
        else:
            total_penalty = sum(
                _SEVERITY_WEIGHT.get(getattr(f, "severity", "info").lower(), 2)
                for f in findings
            )
            # Normalise: worst case is all findings critical (weight=100 each)
            worst_case = total * _SEVERITY_WEIGHT["critical"]
            score = max(0.0, 100.0 - (total_penalty / worst_case * 100.0))

        return ComplianceReport(
            overall_score=round(score, 1),
            total_findings=total,
            findings_by_severity=dict(findings_by_severity),
            findings_by_provider=dict(findings_by_provider),
            control_gaps=list(control_map.values()),
            metadata=metadata,
            generated_at=generated_at,
        )


# ── Multi-Framework ComplianceReporter ────────────────────────────────────────

# Framework control families / categories
_FRAMEWORK_CONTROLS: Dict[str, Dict[str, List[str]]] = {
    "NIST_800_53": {
        "Access Control":        ["AC-1",  "AC-2",  "AC-3",  "AC-5",  "AC-6",  "AC-17"],
        "Audit & Accountability": ["AU-2",  "AU-6",  "AU-9",  "AU-12"],
        "Configuration Mgmt":    ["CM-2",  "CM-6",  "CM-7",  "CM-8"],
        "Contingency Planning":  ["CP-9",  "CP-10"],
        "Identification & Auth": ["IA-2",  "IA-3",  "IA-5",  "IA-8"],
        "Incident Response":     ["IR-4",  "IR-5",  "IR-6"],
        "Risk Assessment":       ["RA-3",  "RA-5",  "RA-7"],
        "System & Comm Prot":    ["SC-7",  "SC-8",  "SC-12", "SC-13", "SC-28"],
        "System & Info Integ":   ["SI-2",  "SI-3",  "SI-10"],
    },
    "NIST_AI_RMF": {
        "Govern":   ["GOVERN-1", "GOVERN-2", "GOVERN-3", "GOVERN-4", "GOVERN-5", "GOVERN-6"],
        "Map":      ["MAP-1",    "MAP-2",    "MAP-3",    "MAP-4",    "MAP-5"],
        "Measure":  ["MEASURE-1","MEASURE-2","MEASURE-3","MEASURE-4"],
        "Manage":   ["MANAGE-1", "MANAGE-2", "MANAGE-3", "MANAGE-4"],
    },
    "OWASP_LLM": {
        "Prompt Injection":       ["LLM01"],
        "Insecure Output Handling":["LLM02"],
        "Training Data Poisoning":["LLM03"],
        "Model Denial of Service":["LLM04"],
        "Supply Chain Vulns":     ["LLM05"],
        "Sensitive Info Disclosure":["LLM06"],
        "Insecure Plugin Design": ["LLM07"],
        "Excessive Agency":       ["LLM08"],
        "Overreliance":           ["LLM09"],
        "Model Theft":            ["LLM10"],
    },
    "EU_AI_ACT": {
        "Risk Management":        ["AIA-9",  "AIA-10"],
        "Data Governance":        ["AIA-10", "AIA-17"],
        "Technical Documentation":["AIA-11"],
        "Transparency":           ["AIA-13"],
        "Human Oversight":        ["AIA-14"],
        "Accuracy & Robustness":  ["AIA-15"],
        "Cybersecurity":          ["AIA-15", "AIA-16"],
    },
    "ISO_42001": {
        "AI Management System":   ["ISO42-4", "ISO42-5", "ISO42-6"],
        "Risk Assessment":        ["ISO42-6.1", "ISO42-8.4"],
        "AI Policy":              ["ISO42-5.2", "ISO42-6.2"],
        "Operational Planning":   ["ISO42-8",  "ISO42-8.3"],
        "Performance Evaluation": ["ISO42-9",  "ISO42-9.1"],
        "Continual Improvement":  ["ISO42-10"],
    },
}

# Maps finding severity → compliance impact label
_IMPACT_LABEL: Dict[str, str] = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Informational",
}

# Framework display names
_FRAMEWORK_NAMES: Dict[str, str] = {
    "NIST_800_53":  "NIST 800-53 Rev5",
    "NIST_AI_RMF":  "NIST AI RMF",
    "OWASP_LLM":    "OWASP LLM Top 10",
    "EU_AI_ACT":    "EU AI Act",
    "ISO_42001":    "ISO 42001",
}


@dataclass
class FrameworkSection:
    """One control family / category within a framework."""
    family: str
    controls: List[str]
    findings: List[Any] = field(default_factory=list)

    @property
    def compliant(self) -> bool:
        return len(self.findings) == 0

    @property
    def max_severity(self) -> str:
        order = ["critical", "high", "medium", "low", "info"]
        for sev in order:
            if any(getattr(f, "severity", "info") == sev for f in self.findings):
                return sev
        return "info"

    def to_dict(self) -> dict:
        return {
            "family":        self.family,
            "controls":      self.controls,
            "compliant":     self.compliant,
            "finding_count": len(self.findings),
            "max_severity":  self.max_severity if self.findings else None,
        }


@dataclass
class MultiFrameworkReport:
    """
    Compliance report spanning one or more frameworks.

    Attributes:
        framework        — Framework key (e.g. ``"NIST_800_53"``)
        framework_name   — Human-readable framework name
        overall_score    — 0-100 compliance score
        sections         — Per-family control gap analysis
        findings_summary — {severity: count} across all findings
        tenant_id        — Tenant this report belongs to
        metadata         — Caller-supplied extras
        generated_at     — ISO-8601 UTC timestamp
    """
    framework: str
    framework_name: str
    overall_score: float
    sections: List[FrameworkSection]
    findings_summary: Dict[str, int]
    tenant_id: str
    metadata: Dict[str, Any]
    generated_at: str

    def to_dict(self) -> dict:
        return {
            "framework":        self.framework,
            "framework_name":   self.framework_name,
            "overall_score":    round(self.overall_score, 1),
            "sections":         [s.to_dict() for s in self.sections],
            "findings_summary": self.findings_summary,
            "tenant_id":        self.tenant_id,
            "metadata":         self.metadata,
            "generated_at":     self.generated_at,
        }

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), indent=2)

    def to_markdown(self) -> str:
        """Render this report as a Markdown string."""
        lines: List[str] = []
        lines.append(f"# {self.framework_name} Compliance Report")
        lines.append("")
        lines.append(f"**Generated:** {self.generated_at}")
        lines.append(f"**Tenant:** {self.tenant_id}")
        lines.append(f"**Overall Score:** {self.overall_score:.1f} / 100")
        lines.append("")
        if self.findings_summary:
            lines.append("## Findings Summary")
            lines.append("")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = self.findings_summary.get(sev, 0)
                if count:
                    lines.append(f"- **{sev.upper()}**: {count}")
            lines.append("")
        lines.append("## Control Families")
        lines.append("")
        for s in self.sections:
            finding_count = len(s.findings)
            status = "PASS" if s.compliant else f"FAIL ({finding_count} finding(s), max: {s.max_severity.upper()})"
            lines.append(f"### {s.family}: {status}")
            for ctrl in s.controls:
                lines.append(f"  - {ctrl}")
            lines.append("")
        if self.metadata:
            lines.append("## Metadata")
            lines.append("")
            for k, v in self.metadata.items():
                lines.append(f"- **{k}**: {v}")
            lines.append("")
        return "\n".join(lines)

    def to_pdf_bytes(self) -> bytes:
        """Generate a PDF report using stdlib only (no reportlab/weasyprint)."""
        md = self.to_markdown()
        lines: List[str] = []
        for raw_line in md.splitlines():
            lines.extend(_wrap_text(raw_line, max_chars=90))
        return _build_pdf_bytes(lines, title=f"{self.framework_name} Compliance Report")

    def to_docx_bytes(self) -> bytes:
        """Generate a DOCX report using stdlib only (no python-docx)."""
        paragraphs = self.to_markdown().splitlines()
        return _build_docx_bytes(paragraphs, title=f"{self.framework_name} Compliance Report")


class ComplianceReporter:
    """
    Multi-framework compliance reporter.

    Generates structured compliance reports for:
      • NIST 800-53 Rev5
      • NIST AI RMF
      • OWASP LLM Top 10
      • EU AI Act

    Takes AI security events / findings as input; produces
    :class:`MultiFrameworkReport` objects suitable for JSON export,
    dashboard display, and eMASS / SSP ingestion.

    Usage::

        reporter = ComplianceReporter(tenant_id="org-123")
        report = reporter.generate(events, framework="NIST_AI_RMF")
        print(report.overall_score)
        print(report.to_json())
    """

    SUPPORTED_FRAMEWORKS = list(_FRAMEWORK_CONTROLS.keys())

    def __init__(self, tenant_id: str = "default") -> None:
        self.tenant_id = tenant_id

    # ── Core generate method ──────────────────────────────────────────────────

    def generate(
        self,
        events: List[Any],
        framework: str = "NIST_800_53",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MultiFrameworkReport:
        """
        Generate a compliance report for *framework* from *events*.

        Args:
            events:     List of dicts or objects with at least:
                        ``severity`` (str), ``event_type`` (str),
                        ``controls`` (List[str]) or ``nist_controls`` (List[str]).
            framework:  One of ``SUPPORTED_FRAMEWORKS``.
            metadata:   Optional dict merged into the report.

        Returns:
            :class:`MultiFrameworkReport`

        Raises:
            ValueError: If *framework* is not supported.
        """
        if framework not in _FRAMEWORK_CONTROLS:
            raise ValueError(
                f"Unsupported framework '{framework}'. "
                f"Choose from: {self.SUPPORTED_FRAMEWORKS}"
            )

        generated_at = datetime.now(timezone.utc).isoformat()
        metadata = metadata or {}
        families = _FRAMEWORK_CONTROLS[framework]

        # Build control → findings index
        ctrl_findings: Dict[str, List[Any]] = defaultdict(list)
        for event in events:
            # Support both Finding objects and plain dicts
            if isinstance(event, dict):
                controls = (
                    event.get("controls")
                    or event.get("nist_controls")
                    or event.get("ai_controls")
                    or []
                )
                sev = event.get("severity", "info")
            else:
                controls = (
                    getattr(event, "controls", None)
                    or getattr(event, "nist_controls", None)
                    or getattr(event, "ai_controls", None)
                    or []
                )
                sev = getattr(event, "severity", "info")

            for ctrl in controls:
                ctrl_findings[ctrl].append(event)

        # Build sections
        sections: List[FrameworkSection] = []
        for family, controls in families.items():
            family_findings: List[Any] = []
            for ctrl in controls:
                family_findings.extend(ctrl_findings.get(ctrl, []))
            # Deduplicate findings in family
            seen_ids: set = set()
            unique: List[Any] = []
            for f in family_findings:
                fid = id(f)
                if fid not in seen_ids:
                    seen_ids.add(fid)
                    unique.append(f)
            sections.append(FrameworkSection(
                family=family,
                controls=controls,
                findings=unique,
            ))

        # Score: percent of families with zero findings
        if not sections:
            score = 100.0
        else:
            # Weight by severity — fewer critical gaps = higher score
            penalty = 0.0
            for s in sections:
                if not s.compliant:
                    w = _SEVERITY_WEIGHT.get(s.max_severity, 2)
                    penalty += w
            max_penalty = len(sections) * _SEVERITY_WEIGHT["critical"]
            score = max(0.0, 100.0 - (penalty / max_penalty * 100.0))

        # Findings summary
        findings_summary: Dict[str, int] = defaultdict(int)
        for event in events:
            sev = (
                event.get("severity", "info")
                if isinstance(event, dict)
                else getattr(event, "severity", "info")
            )
            findings_summary[sev.lower()] += 1

        return MultiFrameworkReport(
            framework=framework,
            framework_name=_FRAMEWORK_NAMES[framework],
            overall_score=round(score, 1),
            sections=sections,
            findings_summary=dict(findings_summary),
            tenant_id=self.tenant_id,
            metadata=metadata,
            generated_at=generated_at,
        )

    def generate_all_frameworks(
        self,
        events: List[Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, MultiFrameworkReport]:
        """
        Generate reports for **all** supported frameworks.

        Returns a dict of ``{framework_key: MultiFrameworkReport}``.
        """
        return {
            fw: self.generate(events, framework=fw, metadata=metadata)
            for fw in self.SUPPORTED_FRAMEWORKS
        }

    def summary(
        self,
        events: List[Any],
        frameworks: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Compact summary across multiple frameworks.

        Returns a dict suitable for a dashboard panel:
        ``{framework_name: {score, sections_failing}}``.
        """
        if frameworks is None:
            frameworks = self.SUPPORTED_FRAMEWORKS
        out: Dict[str, Any] = {}
        for fw in frameworks:
            try:
                report = self.generate(events, framework=fw)
                failing = sum(1 for s in report.sections if not s.compliant)
                out[report.framework_name] = {
                    "score":           report.overall_score,
                    "sections_total":  len(report.sections),
                    "sections_failing": failing,
                    "findings_total":  sum(report.findings_summary.values()),
                }
            except ValueError:
                pass
        return out


# ── AIComplianceReporter ───────────────────────────────────────────────────────────────

# Mapping from AI event_type / violation_type → framework controls
_AI_EVENT_CONTROL_MAP: Dict[str, Dict[str, List[str]]] = {
    "prompt_injection":        {"NIST_AI_RMF": ["GOVERN-1", "MAP-5", "MANAGE-4"],
                                "OWASP_LLM":   ["LLM01"],
                                "EU_AI_ACT":   ["AIA-15", "AIA-16"],
                                "ISO_42001":   ["ISO42-8.4"]},
    "jailbreak":               {"NIST_AI_RMF": ["GOVERN-2", "MANAGE-3"],
                                "OWASP_LLM":   ["LLM01"],
                                "EU_AI_ACT":   ["AIA-15"],
                                "ISO_42001":   ["ISO42-8"]},
    "data_exfiltration":       {"NIST_AI_RMF": ["MANAGE-4", "MEASURE-2"],
                                "OWASP_LLM":   ["LLM06"],
                                "EU_AI_ACT":   ["AIA-10", "AIA-17"],
                                "ISO_42001":   ["ISO42-6.1"]},
    "pii_detected":            {"NIST_AI_RMF": ["GOVERN-4", "MANAGE-1"],
                                "OWASP_LLM":   ["LLM06"],
                                "EU_AI_ACT":   ["AIA-10"],
                                "ISO_42001":   ["ISO42-8.4"]},
    "policy_violation":        {"NIST_AI_RMF": ["GOVERN-1", "GOVERN-6"],
                                "OWASP_LLM":   ["LLM08"],
                                "EU_AI_ACT":   ["AIA-9", "AIA-14"],
                                "ISO_42001":   ["ISO42-5.2"]},
    "model_denial_of_service": {"NIST_AI_RMF": ["MANAGE-2", "MEASURE-3"],
                                "OWASP_LLM":   ["LLM04"],
                                "EU_AI_ACT":   ["AIA-15"],
                                "ISO_42001":   ["ISO42-8.3"]},
    "training_data_poisoning": {"NIST_AI_RMF": ["GOVERN-3", "MAP-3"],
                                "OWASP_LLM":   ["LLM03"],
                                "EU_AI_ACT":   ["AIA-10"],
                                "ISO_42001":   ["ISO42-8.4"]},
    "supply_chain_vuln":       {"NIST_AI_RMF": ["MAP-5", "MEASURE-4"],
                                "OWASP_LLM":   ["LLM05"],
                                "EU_AI_ACT":   ["AIA-16"],
                                "ISO_42001":   ["ISO42-8"]},
    "model_theft":             {"NIST_AI_RMF": ["MANAGE-3", "MEASURE-2"],
                                "OWASP_LLM":   ["LLM10"],
                                "EU_AI_ACT":   ["AIA-16"],
                                "ISO_42001":   ["ISO42-9"]},
    "excessive_agency":        {"NIST_AI_RMF": ["GOVERN-5", "MANAGE-2"],
                                "OWASP_LLM":   ["LLM08"],
                                "EU_AI_ACT":   ["AIA-14"],
                                "ISO_42001":   ["ISO42-6.2"]},
    "insecure_output":         {"NIST_AI_RMF": ["MANAGE-1", "MEASURE-1"],
                                "OWASP_LLM":   ["LLM02"],
                                "EU_AI_ACT":   ["AIA-13"],
                                "ISO_42001":   ["ISO42-9.1"]},
    "insecure_plugin":         {"NIST_AI_RMF": ["MAP-4", "MANAGE-4"],
                                "OWASP_LLM":   ["LLM07"],
                                "EU_AI_ACT":   ["AIA-16"],
                                "ISO_42001":   ["ISO42-8.3"]},
    "overreliance":            {"NIST_AI_RMF": ["GOVERN-4", "MAP-2"],
                                "OWASP_LLM":   ["LLM09"],
                                "EU_AI_ACT":   ["AIA-13", "AIA-14"],
                                "ISO_42001":   ["ISO42-10"]},
}

# Frameworks covered by AIComplianceReporter
_AI_FRAMEWORKS: List[str] = ["NIST_AI_RMF", "OWASP_LLM", "EU_AI_ACT", "ISO_42001"]


@dataclass
class AIComplianceReport:
    """
    AI-specific compliance report spanning NIST AI RMF, OWASP LLM Top 10,
    EU AI Act, and ISO 42001.

    Attributes:
        frameworks          — {framework_key: MultiFrameworkReport}
        event_count         — Total AI events analysed
        violation_count     — Events with mapped violations
        overall_risk_score  — 0-100 mean score across all frameworks (higher = better)
        tenant_id           — Tenant context
        generated_at        — ISO-8601 UTC timestamp
    """
    frameworks: Dict[str, MultiFrameworkReport]
    event_count: int
    violation_count: int
    overall_risk_score: float
    tenant_id: str
    generated_at: str

    def to_dict(self) -> dict:
        return {
            "frameworks":         {k: v.to_dict() for k, v in self.frameworks.items()},
            "event_count":        self.event_count,
            "violation_count":    self.violation_count,
            "overall_risk_score": round(self.overall_risk_score, 1),
            "tenant_id":          self.tenant_id,
            "generated_at":       self.generated_at,
        }

    def to_markdown(self) -> str:
        lines: List[str] = []
        lines.append("# Aegis AI Security Compliance Report")
        lines.append("")
        lines.append(f"**Generated:** {self.generated_at}")
        lines.append(f"**Tenant:** {self.tenant_id}")
        lines.append(f"**Events Analysed:** {self.event_count}")
        lines.append(f"**Violations Detected:** {self.violation_count}")
        lines.append(f"**Overall Risk Score:** {self.overall_risk_score:.1f} / 100")
        lines.append("")
        lines.append("## Framework Scores")
        lines.append("")
        for _fw_key, report in self.frameworks.items():
            lines.append(f"- **{report.framework_name}**: {report.overall_score:.1f} / 100")
        lines.append("")
        for _fw_key, report in self.frameworks.items():
            lines.append("---")
            lines.append(report.to_markdown())
            lines.append("")
        return "\n".join(lines)

    def to_pdf_bytes(self) -> bytes:
        """Generate a PDF report using stdlib only."""
        md = self.to_markdown()
        raw_lines: List[str] = []
        for raw_line in md.splitlines():
            raw_lines.extend(_wrap_text(raw_line, max_chars=90))
        return _build_pdf_bytes(raw_lines, title="Aegis AI Security Compliance Report")

    def to_docx_bytes(self) -> bytes:
        """Generate a DOCX report using stdlib only."""
        return _build_docx_bytes(
            self.to_markdown().splitlines(),
            title="Aegis AI Security Compliance Report",
        )


class AIComplianceReporter:
    """
    AI security compliance reporter.

    Maps AI security events and policy violations to compliance frameworks:
      - NIST AI RMF  (Govern / Map / Measure / Manage)
      - OWASP LLM Top 10
      - EU AI Act
      - ISO 42001

    Usage::

        reporter = AIComplianceReporter(tenant_id="org-456")
        report = reporter.generate(events)
        print(report.overall_risk_score)
        pdf = report.to_pdf_bytes()
        docx = report.to_docx_bytes()
    """

    SUPPORTED_FRAMEWORKS: List[str] = _AI_FRAMEWORKS

    def __init__(self, tenant_id: str = "default") -> None:
        self.tenant_id = tenant_id
        self._reporter = ComplianceReporter(tenant_id=tenant_id)

    def _enrich_events(self, events: List[Any]) -> List[dict]:
        """Inject framework control mappings based on event_type."""
        enriched: List[dict] = []
        for event in events:
            if isinstance(event, dict):
                ev: dict = dict(event)
                event_type: str = ev.get("event_type") or ev.get("violation_type") or ""
            else:
                ev = {
                    "severity": getattr(event, "severity", "info"),
                    "event_type": (
                        getattr(event, "event_type", None)
                        or getattr(event, "violation_type", None)
                        or ""
                    ),
                }
                event_type = str(ev["event_type"])
            mapping = _AI_EVENT_CONTROL_MAP.get(event_type, {})
            ev["_framework_controls"] = mapping
            enriched.append(ev)
        return enriched

    def generate(
        self,
        events: List[Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AIComplianceReport:
        """
        Generate an AI compliance report across all supported frameworks.

        Args:
            events:   List of AI security events (dicts or objects).
                      Each event should have ``event_type`` (str) and
                      ``severity`` (str).  Unknown event_types still count
                      toward totals but produce no control mappings.
            metadata: Optional dict merged into each sub-report.

        Returns:
            :class:`AIComplianceReport`
        """
        generated_at = datetime.now(timezone.utc).isoformat()
        metadata = metadata or {}
        enriched = self._enrich_events(events)

        fw_events: Dict[str, List[dict]] = {fw: [] for fw in _AI_FRAMEWORKS}
        violation_count = 0

        for ev in enriched:
            ctrl_map: Dict[str, List[str]] = ev.get("_framework_controls", {})
            if ctrl_map:
                violation_count += 1
            for fw in _AI_FRAMEWORKS:
                fw_ev = dict(ev)
                fw_ev["controls"] = ctrl_map.get(fw, [])
                fw_events[fw].append(fw_ev)

        fw_reports: Dict[str, MultiFrameworkReport] = {}
        for fw in _AI_FRAMEWORKS:
            fw_reports[fw] = self._reporter.generate(
                fw_events[fw], framework=fw, metadata=metadata
            )

        overall: float = (
            sum(r.overall_score for r in fw_reports.values()) / len(fw_reports)
            if fw_reports
            else 100.0
        )

        return AIComplianceReport(
            frameworks=fw_reports,
            event_count=len(events),
            violation_count=violation_count,
            overall_risk_score=round(overall, 1),
            tenant_id=self.tenant_id,
            generated_at=generated_at,
        )

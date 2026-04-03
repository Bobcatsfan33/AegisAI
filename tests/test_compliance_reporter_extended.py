"""
Extended tests for compliance.py — PDF/DOCX export and AIComplianceReporter.

Covers:
  ComplianceReport.to_pdf_bytes()   → valid PDF (stdlib, no reportlab)
  ComplianceReport.to_docx_bytes()  → valid DOCX/ZIP
  MultiFrameworkReport.to_pdf_bytes()
  MultiFrameworkReport.to_docx_bytes()
  MultiFrameworkReport.to_markdown()
  AIComplianceReporter.generate()
  AIComplianceReport.to_dict()
  AIComplianceReport.to_markdown()
  AIComplianceReport.to_pdf_bytes()
  AIComplianceReport.to_docx_bytes()
  ISO 42001 framework coverage
"""
from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from typing import List

import pytest

from modules.reports.compliance import (
    AIComplianceReport,
    AIComplianceReporter,
    ComplianceReport,
    ComplianceReportGenerator,
    ComplianceReporter,
    MultiFrameworkReport,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@dataclass
class MockFinding:
    resource: str = "arn:aws:s3:::bucket"
    issue: str = "Public bucket"
    severity: str = "high"
    provider: str = "aws"
    nist_controls: List[str] = field(default_factory=lambda: ["AC-3", "CM-6"])
    remediation_hint: str = "Enable block public access"


def _finding(severity: str = "high", controls: list | None = None) -> MockFinding:
    return MockFinding(
        severity=severity,
        nist_controls=controls or ["AC-3"],
    )


def _event(event_type: str = "prompt_injection", severity: str = "high") -> dict:
    return {"event_type": event_type, "severity": severity}


# ── ComplianceReport PDF/DOCX ─────────────────────────────────────────────────


class TestComplianceReportPDF:
    def setup_method(self):
        gen = ComplianceReportGenerator()
        self.report = gen.generate([_finding("high"), _finding("critical")])

    def test_pdf_returns_bytes(self):
        result = self.report.to_pdf_bytes()
        assert isinstance(result, bytes)

    def test_pdf_starts_with_header(self):
        pdf = self.report.to_pdf_bytes()
        assert pdf[:4] == b"%PDF"

    def test_pdf_nonempty(self):
        pdf = self.report.to_pdf_bytes()
        assert len(pdf) > 200

    def test_pdf_contains_eof_marker(self):
        pdf = self.report.to_pdf_bytes()
        assert b"%%EOF" in pdf

    def test_pdf_empty_findings(self):
        gen = ComplianceReportGenerator()
        empty_report = gen.generate([])
        pdf = empty_report.to_pdf_bytes()
        assert pdf[:4] == b"%PDF"

    def test_pdf_many_findings(self):
        gen = ComplianceReportGenerator()
        findings = [_finding("medium") for _ in range(50)]
        big_report = gen.generate(findings)
        pdf = big_report.to_pdf_bytes()
        assert pdf[:4] == b"%PDF"


class TestComplianceReportDOCX:
    def setup_method(self):
        gen = ComplianceReportGenerator()
        self.report = gen.generate([_finding("high")])

    def test_docx_returns_bytes(self):
        result = self.report.to_docx_bytes()
        assert isinstance(result, bytes)

    def test_docx_starts_with_pk_magic(self):
        docx = self.report.to_docx_bytes()
        assert docx[:2] == b"PK"

    def test_docx_is_valid_zip(self):
        docx = self.report.to_docx_bytes()
        buf = io.BytesIO(docx)
        assert zipfile.is_zipfile(buf)

    def test_docx_contains_document_xml(self):
        docx = self.report.to_docx_bytes()
        buf = io.BytesIO(docx)
        with zipfile.ZipFile(buf) as zf:
            assert "word/document.xml" in zf.namelist()

    def test_docx_contains_content_types(self):
        docx = self.report.to_docx_bytes()
        buf = io.BytesIO(docx)
        with zipfile.ZipFile(buf) as zf:
            assert "[Content_Types].xml" in zf.namelist()

    def test_docx_contains_styles_xml(self):
        docx = self.report.to_docx_bytes()
        buf = io.BytesIO(docx)
        with zipfile.ZipFile(buf) as zf:
            assert "word/styles.xml" in zf.namelist()

    def test_docx_document_xml_has_content(self):
        docx = self.report.to_docx_bytes()
        buf = io.BytesIO(docx)
        with zipfile.ZipFile(buf) as zf:
            content = zf.read("word/document.xml")
        assert b"NIST" in content or b"Compliance" in content or b"Aegis" in content

    def test_docx_empty_findings(self):
        gen = ComplianceReportGenerator()
        empty_report = gen.generate([])
        docx = empty_report.to_docx_bytes()
        assert docx[:2] == b"PK"


# ── MultiFrameworkReport PDF/DOCX/Markdown ────────────────────────────────────


class TestMultiFrameworkReportExport:
    def setup_method(self):
        reporter = ComplianceReporter(tenant_id="test-tenant")
        events = [_event("prompt_injection", "high"), _event("pii_detected", "medium")]
        self.report = reporter.generate(events, framework="NIST_AI_RMF")

    def test_to_markdown_returns_string(self):
        md = self.report.to_markdown()
        assert isinstance(md, str)

    def test_to_markdown_contains_framework_name(self):
        md = self.report.to_markdown()
        assert "NIST AI RMF" in md

    def test_to_markdown_contains_score(self):
        md = self.report.to_markdown()
        assert "Overall Score" in md

    def test_to_markdown_contains_sections(self):
        md = self.report.to_markdown()
        assert "Govern" in md or "Map" in md

    def test_to_pdf_returns_valid_pdf(self):
        pdf = self.report.to_pdf_bytes()
        assert pdf[:4] == b"%PDF"

    def test_to_pdf_nonempty(self):
        pdf = self.report.to_pdf_bytes()
        assert len(pdf) > 200

    def test_to_docx_returns_valid_zip(self):
        docx = self.report.to_docx_bytes()
        assert docx[:2] == b"PK"
        assert zipfile.is_zipfile(io.BytesIO(docx))

    def test_to_docx_contains_document_xml(self):
        docx = self.report.to_docx_bytes()
        with zipfile.ZipFile(io.BytesIO(docx)) as zf:
            assert "word/document.xml" in zf.namelist()


# ── AIComplianceReporter ──────────────────────────────────────────────────────


class TestAIComplianceReporter:
    def setup_method(self):
        self.reporter = AIComplianceReporter(tenant_id="org-test")

    def test_generate_returns_ai_compliance_report(self):
        report = self.reporter.generate([])
        assert isinstance(report, AIComplianceReport)

    def test_generate_empty_events_score_100(self):
        report = self.reporter.generate([])
        assert report.overall_risk_score == 100.0

    def test_generate_empty_no_violations(self):
        report = self.reporter.generate([])
        assert report.violation_count == 0

    def test_generate_empty_event_count_0(self):
        report = self.reporter.generate([])
        assert report.event_count == 0

    def test_generate_with_events_event_count(self):
        events = [_event("prompt_injection"), _event("pii_detected")]
        report = self.reporter.generate(events)
        assert report.event_count == 2

    def test_generate_prompt_injection_counted_as_violation(self):
        report = self.reporter.generate([_event("prompt_injection", "critical")])
        assert report.violation_count == 1

    def test_generate_unknown_event_type_not_counted_as_violation(self):
        report = self.reporter.generate([{"event_type": "unknown_xyz", "severity": "high"}])
        assert report.violation_count == 0

    def test_generate_contains_nist_ai_rmf(self):
        report = self.reporter.generate([])
        assert "NIST_AI_RMF" in report.frameworks

    def test_generate_contains_owasp_llm(self):
        report = self.reporter.generate([])
        assert "OWASP_LLM" in report.frameworks

    def test_generate_contains_eu_ai_act(self):
        report = self.reporter.generate([])
        assert "EU_AI_ACT" in report.frameworks

    def test_generate_contains_iso_42001(self):
        report = self.reporter.generate([])
        assert "ISO_42001" in report.frameworks

    def test_generate_tenant_id_propagated(self):
        report = self.reporter.generate([])
        assert report.tenant_id == "org-test"
        for fw_report in report.frameworks.values():
            assert fw_report.tenant_id == "org-test"

    def test_generate_generated_at_present(self):
        report = self.reporter.generate([])
        assert report.generated_at

    def test_prompt_injection_maps_to_nist_ai_rmf_govern(self):
        events = [_event("prompt_injection", "critical")]
        report = self.reporter.generate(events)
        nist = report.frameworks["NIST_AI_RMF"]
        govern = next(s for s in nist.sections if s.family == "Govern")
        assert not govern.compliant

    def test_prompt_injection_maps_to_owasp_llm01(self):
        events = [_event("prompt_injection", "critical")]
        report = self.reporter.generate(events)
        owasp = report.frameworks["OWASP_LLM"]
        pi_section = next(s for s in owasp.sections if "Prompt Injection" in s.family)
        assert not pi_section.compliant

    def test_pii_detected_maps_to_owasp_llm06(self):
        events = [_event("pii_detected", "high")]
        report = self.reporter.generate(events)
        owasp = report.frameworks["OWASP_LLM"]
        sdi = next(s for s in owasp.sections if "Sensitive" in s.family)
        assert not sdi.compliant

    def test_policy_violation_maps_to_eu_ai_act(self):
        events = [_event("policy_violation", "medium")]
        report = self.reporter.generate(events)
        eu = report.frameworks["EU_AI_ACT"]
        # AIA-9 and AIA-14 → Risk Management and Human Oversight
        failing = [s for s in eu.sections if not s.compliant]
        assert len(failing) >= 1

    def test_excessive_agency_maps_to_iso_42001(self):
        events = [_event("excessive_agency", "high")]
        report = self.reporter.generate(events)
        iso = report.frameworks["ISO_42001"]
        failing = [s for s in iso.sections if not s.compliant]
        assert len(failing) >= 1

    def test_score_drops_with_violations(self):
        events = [
            _event("prompt_injection", "critical"),
            _event("data_exfiltration", "critical"),
            _event("jailbreak", "critical"),
        ]
        report = self.reporter.generate(events)
        assert report.overall_risk_score < 100.0

    def test_all_known_event_types_accepted(self):
        known_types = [
            "prompt_injection", "jailbreak", "data_exfiltration", "pii_detected",
            "policy_violation", "model_denial_of_service", "training_data_poisoning",
            "supply_chain_vuln", "model_theft", "excessive_agency",
            "insecure_output", "insecure_plugin", "overreliance",
        ]
        events = [_event(t, "high") for t in known_types]
        report = self.reporter.generate(events)
        assert report.violation_count == len(known_types)


# ── AIComplianceReport export methods ────────────────────────────────────────


class TestAIComplianceReportExport:
    def setup_method(self):
        reporter = AIComplianceReporter(tenant_id="export-test")
        events = [
            _event("prompt_injection", "critical"),
            _event("pii_detected", "high"),
        ]
        self.report = reporter.generate(events)

    def test_to_dict_returns_dict(self):
        d = self.report.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_has_frameworks(self):
        d = self.report.to_dict()
        assert "frameworks" in d
        assert "NIST_AI_RMF" in d["frameworks"]

    def test_to_dict_has_counts(self):
        d = self.report.to_dict()
        assert d["event_count"] == 2
        assert d["violation_count"] == 2

    def test_to_dict_has_risk_score(self):
        d = self.report.to_dict()
        assert "overall_risk_score" in d
        assert isinstance(d["overall_risk_score"], float)

    def test_to_markdown_returns_string(self):
        md = self.report.to_markdown()
        assert isinstance(md, str)

    def test_to_markdown_contains_header(self):
        md = self.report.to_markdown()
        assert "AI Security Compliance Report" in md

    def test_to_markdown_contains_all_frameworks(self):
        md = self.report.to_markdown()
        assert "NIST AI RMF" in md
        assert "OWASP LLM" in md
        assert "EU AI Act" in md
        assert "ISO 42001" in md

    def test_to_pdf_returns_valid_pdf(self):
        pdf = self.report.to_pdf_bytes()
        assert pdf[:4] == b"%PDF"
        assert len(pdf) > 200

    def test_to_docx_returns_valid_zip(self):
        docx = self.report.to_docx_bytes()
        assert docx[:2] == b"PK"
        assert zipfile.is_zipfile(io.BytesIO(docx))

    def test_to_docx_has_document_xml(self):
        docx = self.report.to_docx_bytes()
        with zipfile.ZipFile(io.BytesIO(docx)) as zf:
            assert "word/document.xml" in zf.namelist()

    def test_to_pdf_empty_events(self):
        reporter = AIComplianceReporter()
        report = reporter.generate([])
        pdf = report.to_pdf_bytes()
        assert pdf[:4] == b"%PDF"

    def test_to_docx_empty_events(self):
        reporter = AIComplianceReporter()
        report = reporter.generate([])
        docx = report.to_docx_bytes()
        assert docx[:2] == b"PK"


# ── ISO 42001 framework ───────────────────────────────────────────────────────


class TestISO42001Framework:
    def setup_method(self):
        self.reporter = ComplianceReporter(tenant_id="iso-test")

    def test_iso_42001_in_supported_frameworks(self):
        assert "ISO_42001" in ComplianceReporter.SUPPORTED_FRAMEWORKS

    def test_iso_42001_generates_report(self):
        report = self.reporter.generate([], framework="ISO_42001")
        assert report.framework == "ISO_42001"
        assert report.framework_name == "ISO 42001"

    def test_iso_42001_has_sections(self):
        report = self.reporter.generate([], framework="ISO_42001")
        assert len(report.sections) > 0

    def test_iso_42001_section_names(self):
        report = self.reporter.generate([], framework="ISO_42001")
        families = {s.family for s in report.sections}
        assert "AI Management System" in families
        assert "Risk Assessment" in families

    def test_iso_42001_empty_score_100(self):
        report = self.reporter.generate([], framework="ISO_42001")
        assert report.overall_score == 100.0

    def test_iso_42001_event_mapping(self):
        events = [{"severity": "high", "controls": ["ISO42-8.4"], "event_type": "test"}]
        report = self.reporter.generate(events, framework="ISO_42001")
        # ISO42-8.4 maps to AI Management System or Risk Assessment
        failing = [s for s in report.sections if not s.compliant]
        assert len(failing) >= 1

    def test_iso_42001_to_pdf(self):
        report = self.reporter.generate([], framework="ISO_42001")
        pdf = report.to_pdf_bytes()
        assert pdf[:4] == b"%PDF"

    def test_iso_42001_to_docx(self):
        report = self.reporter.generate([], framework="ISO_42001")
        docx = report.to_docx_bytes()
        assert docx[:2] == b"PK"

    def test_iso_42001_in_generate_all_frameworks(self):
        reports = self.reporter.generate_all_frameworks([])
        assert "ISO_42001" in reports

    def test_iso_42001_in_summary(self):
        summary = self.reporter.summary([])
        assert "ISO 42001" in summary

import pytest
from pathlib import Path
from penflow.reporting.report_generator import ReportGenerator
from penflow.reporting.export.exporter import ReportExporter
from penflow.validation.confidence_scorer import ScoredFinding
from penflow.validation.fp_filter import ValidatedFinding
from penflow.scanner.context_engine import Finding

def test_report_generation_and_export(tmp_path, monkeypatch):
    # Mock get_scan_dir to use tmp_path
    monkeypatch.setattr("penflow.reporting.report_generator.get_scan_dir", lambda target: tmp_path)
    
    # Create sample findings
    finding = Finding(
        vuln_type="SQLI",
        url="http://example.com/api",
        method="GET",
        param="id",
        payload="' OR 1=1--",
        confidence=0.9,
        raw_request="GET /api?id=' OR 1=1-- HTTP/1.1",
        raw_response="HTTP/1.1 500 SQL syntax error"
    )
    
    val_finding = ValidatedFinding(finding, "reproduction", "SQL error message detected", True)
    scored = ScoredFinding(val_finding, 0.95, "CERTAIN")
    
    generator = ReportGenerator()
    md_path = generator.generate_markdown("example.com", [scored])
    
    assert md_path.exists()
    assert md_path.suffix == ".md"
    
    # Test HTML export
    html_path = ReportExporter.export_html(md_path)
    assert html_path.exists()
    assert html_path.suffix == ".html"
    
    # Read HTML and verify style contents
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
        assert "SQL Injection" in html_content
        assert "example.com" in html_content
        assert "severity-badge" in html_content

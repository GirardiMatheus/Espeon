import pytest
import os
from scanner.report_generator import ReportGenerator

def test_analyze_security():
    report_gen = ReportGenerator()
    scan_results = {
        "ports": [
            {"port": 80, "name": "http", "product": "Apache", "version": "2.4"},
            {"port": 5432, "name": "postgresql", "product": "PostgreSQL", "version": "9.6"}
        ]
    }
    analysis = report_gen.analyze_security(scan_results)

    assert 80 in analysis
    assert 5432 in analysis
    assert analysis[80] == "No specific issues identified for http (Apache 2.4)."
    assert "Potential outdated PostgreSQL version detected" in analysis[5432]

def test_generate_text_report():
    report_gen = ReportGenerator()
    results = {
        "host": "localhost",
        "status": "up",
        "ports": [
            {"port": 80, "state": "open", "name": "http", "product": "Apache", "version": "2.4"},
        ],
        "security_analysis": {80: "No specific issues."},
        "vulnerabilities": {"http_80": [{"id": "CVE-1", "severity": "HIGH", "description": "desc", "published_date": "2023-01-01"}]}
    }
    text = report_gen.generate_text_report(results)
    assert "Host: localhost" in text
    assert "No specific issues." in text
    assert "CVE-1" in text

def test_generate_json_report(tmp_path):
    report_gen = ReportGenerator()
    results = {"host": "localhost", "ports": []}
    output_file = tmp_path / "report.json"
    report_gen.generate_json_report(results, str(output_file))
    assert output_file.exists()
    import json
    with open(output_file) as f:
        data = json.load(f)
    assert data["host"] == "localhost"

def test_generate_csv_report(tmp_path):
    report_gen = ReportGenerator()
    results = {
        "ports": [
            {"port": 80, "state": "open", "name": "http", "product": "Apache", "version": "2.4"},
        ],
        "vulnerabilities": {"http_80": [{"id": "CVE-1", "description": "desc", "severity": "HIGH"}]}
    }
    output_file = tmp_path / "report.csv"
    report_gen.generate_csv_report(results, str(output_file))
    assert output_file.exists()
    with open(output_file) as f:
        content = f.read()
    assert "Port" in content
    assert "CVE-1" in content

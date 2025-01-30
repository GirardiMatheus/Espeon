import pytest
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
import pytest
from scanner.cve_checker import CVEChecker
from unittest.mock import patch, MagicMock

@pytest.fixture
def cve_checker():
    return CVEChecker(api_key="dummy")

@patch("scanner.cve_checker.requests.Session.get")
def test_search_cves_success(mock_get, cve_checker):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-0001",
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseSeverity": "HIGH"}}
                        ]
                    },
                    "descriptions": [
                        {"lang": "en", "value": "Test CVE description"}
                    ],
                    "published": "2023-01-01T00:00Z"
                }
            }
        ]
    }
    mock_response.raise_for_status.return_value = None
    mock_get.return_value = mock_response

    result = cve_checker._search_cves("nginx", "nginx", "1.18")
    assert len(result) == 1
    assert result[0]["id"] == "CVE-2023-0001"
    assert result[0]["severity"] == "HIGH"
    assert "Test CVE description" in result[0]["description"]

def test_score_to_severity(cve_checker):
    assert cve_checker._score_to_severity(9.5) == "CRITICAL"
    assert cve_checker._score_to_severity(7.1) == "HIGH"
    assert cve_checker._score_to_severity(5.5) == "MEDIUM"
    assert cve_checker._score_to_severity(3.9) == "LOW"

@patch("scanner.cve_checker.requests.Session.get")
def test_analyze_results_handles_missing_service_name(mock_get, cve_checker):
    ports = [
        {"port": 80, "product": "nginx", "version": "1.18"},  # missing name
        {"port": 443, "name": "https", "product": "nginx", "version": "1.18"},  # valid
    ]
    mock_response = MagicMock()
    mock_response.json.return_value = {"vulnerabilities": []}
    mock_response.raise_for_status.return_value = None
    mock_get.return_value = mock_response
    result = cve_checker.analyze_results(ports)
    assert "https_443" in result or result == {}

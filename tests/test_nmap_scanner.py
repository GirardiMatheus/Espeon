import pytest
from unittest.mock import patch, MagicMock
from scanner.nmap_integration import NmapScanner

@patch("scanner.nmap_integration.nmap.PortScanner")
def test_scan_host_success(mock_nmap):
    scanner = NmapScanner()

    mock_nmap_instance = mock_nmap.return_value
    mock_nmap_instance.scan.return_value = None
    mock_nmap_instance.all_hosts.return_value = ["127.0.0.1"]

    host_mock = MagicMock()
    host_mock.state.return_value = "up"
    host_mock.all_protocols.return_value = ["tcp"]

    # Ajuste: __getitem__ precisa retornar corretamente para 'tcp' e 'osmatch'
    def get_data(key):
        if key == "tcp":
            return {
                80: {
                    "state": "open",
                    "name": "http",
                    "product": "Apache",
                    "version": "2.4"
                }
            }
        elif key == "osmatch":
            return [
                {
                    "name": "Linux",
                    "accuracy": "95",
                    "line": "1",
                    "osclass": [
                        {"type": "Server", "vendor": "Linux", "osfamily": "Linux", "osgen": "5.X", "accuracy": "95"}
                    ]
                }
            ]
        return {}

    host_mock.__getitem__.side_effect = get_data
    # Para 'osmatch' estar em host_mock, precisa que 'osmatch' in host_mock seja True
    host_mock.__contains__.side_effect = lambda key: key in ["tcp", "osmatch"]

    mock_nmap_instance.__getitem__.side_effect = lambda key: host_mock if key == "127.0.0.1" else MagicMock()

    result = scanner.scan_host("127.0.0.1", "80")

    assert result["host"] == "127.0.0.1"
    assert result["status"] == "up"
    assert len(result["ports"]) > 0
    assert result["ports"][0]["port"] == 80
    assert result["ports"][0]["state"] == "open"
    assert result["ports"][0]["name"] == "http"
    assert result["ports"][0]["product"] == "Apache"
    assert result["ports"][0]["version"] == "2.4"
    assert "os" in result
    assert result["os"][0]["name"] == "Linux"
    assert result["os"][0]["accuracy"] == "95"
    assert result["os"][0]["osclass"][0]["type"] == "Server"



def test_scan_host_no_host_found():
    scanner = NmapScanner()
    with patch.object(scanner.nm, "all_hosts", return_value=[]):
        result = scanner.scan_host("127.0.0.1", "80")
        assert result == {}

import requests
import logging
import time
from typing import List, Dict, Any, Optional
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class CVEChecker:
    """
    Class to query CVE vulnerabilities using the NVD 2.0 API.
    """
    def __init__(
        self,
        api_key: Optional[str] = None,
        results_per_page: int = 10,
        delay: float = 0.6,
        proxies: Optional[Dict[str, str]] = None,
        max_retries: int = 3,
        backoff_factor: float = 0.3
    ):
        """
        :param api_key: NVD API key (optional, but recommended).
        :param results_per_page: Number of results per page.
        :param delay: Delay between requests to respect rate limit.
        :param proxies: Dictionary of proxies for requests.
        :param max_retries: Maximum number of retries for failed requests.
        :param backoff_factor: Backoff factor for retry delays.
        """
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = self._create_retry_session(max_retries, backoff_factor)
        if api_key:
            self.session.headers.update({'apiKey': api_key})
        if proxies:
            self.session.proxies.update(proxies)
        self.results_per_page = results_per_page
        self.delay = delay

    def _create_retry_session(self, max_retries: int, backoff_factor: float) -> requests.Session:
        """
        Creates a session with retry strategy for robust API calls.
        :param max_retries: Maximum number of retries.
        :param backoff_factor: Backoff factor for exponential delays.
        :return: Configured requests session.
        """
        session = requests.Session()
        
        retry_strategy = Retry(
            total=max_retries,
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry
            allowed_methods=["HEAD", "GET", "OPTIONS"],  # HTTP methods to retry
            backoff_factor=backoff_factor,
            raise_on_redirect=False,
            raise_on_status=False
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session

    def analyze_results(self, ports: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Analyzes port results and searches for related CVEs.
        :param ports: List of dictionaries with port/service information.
        :return: Dictionary {service_key: [cves]}
        """
        vulnerabilities = {}
        for port in ports:
            service_name = port.get("name", "").strip()
            product = port.get("product", "").strip() 
            version = port.get("version", "").strip()
            service_key = f"{service_name}_{port.get('port', 'unknown')}"
            if not service_name:
                logging.warning(f"Skipping port {port.get('port')} due to missing service name.")
                vulnerabilities[service_key] = []
                continue
            try:
                cves = self._search_cves(service_name, product, version)
                vulnerabilities[service_key] = cves or []
                if cves:
                    logging.info(f"Found {len(cves)} CVEs for {service_key} ({service_name} {product} {version})")
                else:
                    logging.info(f"No CVEs found for {service_key} ({service_name} {product} {version})")
                time.sleep(self.delay)
            except Exception as e:
                logging.error(f"Error searching CVEs for {service_key}: {e}")
                vulnerabilities[service_key] = []
        return vulnerabilities

    def _search_cves(self, service: str, product: str, version: str) -> List[Dict[str, Any]]:
        """
        Searches for CVEs in the NVD API 2.0.
        :param service: Service name.
        :param product: Product.
        :param version: Version.
        :return: List of CVEs.
        """
        try:
            params = {
                'keywordSearch': f"{service} {product}".strip(),
                'resultsPerPage': self.results_per_page
            }
            if version and version != "N/A":
                params['keywordSearch'] += f" {version}"
            response = self.session.get(self.base_url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            cves = []
            for vulnerability in data.get('vulnerabilities', []):
                cve_data = vulnerability.get('cve', {})
                cve_id = cve_data.get('id', 'Unknown')
                severity = 'Unknown'
                metrics = cve_data.get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    severity = metrics['cvssMetricV31'][0]['cvssData'].get('baseSeverity', 'Unknown')
                elif 'cvssMetricV30' in metrics:
                    severity = metrics['cvssMetricV30'][0]['cvssData'].get('baseSeverity', 'Unknown')
                elif 'cvssMetricV2' in metrics:
                    base_score = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore', 0)
                    severity = self._score_to_severity(base_score)
                descriptions = cve_data.get('descriptions', [])
                description = next((desc.get('value', '') for desc in descriptions if desc.get('lang') == 'en'), 'No description available')
                published_date = cve_data.get('published', cve_data.get('publishedDate', 'Unknown'))
                cves.append({
                    'id': cve_id,
                    'severity': severity,
                    'description': description[:200] + '...' if len(description) > 200 else description,
                    'published_date': published_date
                })
            return cves
        except requests.exceptions.RequestException as e:
            logging.error(f"HTTP error searching CVEs: {e}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error searching CVEs: {e}")
            return []

    def _score_to_severity(self, score: float) -> str:
        """Converts CVSS score to severity."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def save_to_json(self, data: Dict[str, Any], filename: str) -> None:
        """
        Saves the results to a JSON file.
        :param data: Data to be saved.
        :param filename: File path.
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logging.info(f"Results saved to {filename}")
        except Exception as e:
            logging.error(f"Error saving results to {filename}: {e}")
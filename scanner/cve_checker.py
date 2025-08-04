import requests
import time
from typing import List, Dict, Any, Optional
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from utils.logger_config import configure_logging, get_logger
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

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
        backoff_factor: float = 0.3,
        max_workers: int = 4
    ):
        """
        :param api_key: NVD API key (optional, but recommended).
        :param results_per_page: Number of results per page.
        :param delay: Delay between requests to respect rate limit.
        :param proxies: Dictionary of proxies for requests.
        :param max_retries: Maximum number of retries for failed requests.
        :param backoff_factor: Backoff factor for retry delays.
        :param max_workers: Maximum number of concurrent threads.
        """
        self.logger = get_logger(__name__)
        self.logger.debug("Initializing CVEChecker")
        
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = self._create_retry_session(max_retries, backoff_factor)
        if api_key:
            self.session.headers.update({'apiKey': api_key})
            self.logger.debug("API key configured for NVD requests")
        else:
            self.logger.warning("No API key provided - requests may be rate limited")
        if proxies:
            self.session.proxies.update(proxies)
            self.logger.debug(f"Proxies configured: {list(proxies.keys())}")
        self.results_per_page = results_per_page
        self.delay = delay
        self.max_workers = max_workers
        self._rate_limit_lock = threading.Lock()
        
        self.logger.info(f"CVEChecker initialized - results_per_page: {results_per_page}, delay: {delay}s, max_workers: {max_workers}")

    def _create_retry_session(self, max_retries: int, backoff_factor: float) -> requests.Session:
        """
        Creates a session with retry strategy for robust API calls.
        :param max_retries: Maximum number of retries.
        :param backoff_factor: Backoff factor for exponential delays.
        :return: Configured requests session.
        """
        self.logger.debug(f"Creating retry session - max_retries: {max_retries}, backoff_factor: {backoff_factor}")
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
        
        self.logger.debug("Retry session created successfully")
        return session

    def analyze_results(self, ports: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Analyzes port results and searches for related CVEs using concurrent threads.
        :param ports: List of dictionaries with port/service information.
        :return: Dictionary {service_key: [cves]}
        """
        self.logger.info(f"Starting concurrent CVE analysis for {len(ports)} ports using {self.max_workers} workers")
        vulnerabilities = {}
        
        # Prepare tasks for concurrent execution
        tasks = []
        for port in ports:
            service_name = port.get("name", "").strip()
            product = port.get("product", "").strip() 
            version = port.get("version", "").strip()
            service_key = f"{service_name}_{port.get('port', 'unknown')}"
            
            if not service_name:
                self.logger.warning(f"Skipping port {port.get('port')} due to missing service name.")
                vulnerabilities[service_key] = []
                continue
                
            tasks.append((service_key, service_name, product, version))
        
        # Execute CVE searches concurrently
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_service = {
                executor.submit(self._search_cves_with_rate_limit, service_name, product, version): service_key
                for service_key, service_name, product, version in tasks
            }
            
            completed_count = 0
            for future in as_completed(future_to_service):
                service_key = future_to_service[future]
                completed_count += 1
                
                try:
                    cves = future.result()
                    vulnerabilities[service_key] = cves or []
                    if cves:
                        self.logger.info(f"[{completed_count}/{len(tasks)}] Found {len(cves)} CVEs for {service_key}")
                    else:
                        self.logger.info(f"[{completed_count}/{len(tasks)}] No CVEs found for {service_key}")
                except Exception as e:
                    self.logger.error(f"Error searching CVEs for {service_key}: {e}")
                    vulnerabilities[service_key] = []
        
        total_cves = sum(len(cves) for cves in vulnerabilities.values())
        self.logger.info(f"Concurrent CVE analysis completed - found {total_cves} total CVEs across {len(vulnerabilities)} services")
        return vulnerabilities

    def _search_cves_with_rate_limit(self, service: str, product: str, version: str) -> List[Dict[str, Any]]:
        """
        Thread-safe wrapper for _search_cves with rate limiting.
        :param service: Service name.
        :param product: Product.
        :param version: Version.
        :return: List of CVEs.
        """
        # Apply rate limiting across all threads
        with self._rate_limit_lock:
            time.sleep(self.delay)
        
        return self._search_cves(service, product, version)

    def _search_cves(self, service: str, product: str, version: str) -> List[Dict[str, Any]]:
        """
        Searches for CVEs in the NVD API 2.0.
        :param service: Service name.
        :param product: Product.
        :param version: Version.
        :return: List of CVEs.
        """
        self.logger.debug(f"Searching CVEs for service: {service}, product: {product}, version: {version}")
        
        try:
            params = {
                'keywordSearch': f"{service} {product}".strip(),
                'resultsPerPage': self.results_per_page
            }
            if version and version != "N/A":
                params['keywordSearch'] += f" {version}"
            
            self.logger.debug(f"NVD API request params: {params}")
            response = self.session.get(self.base_url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            total_results = data.get('totalResults', 0)
            self.logger.debug(f"NVD API returned {total_results} total results")
            
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
            
            self.logger.debug(f"Processed {len(cves)} CVEs from API response")
            return cves
        except requests.exceptions.RequestException as e:
            self.logger.error(f"HTTP error searching CVEs: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error searching CVEs: {e}")
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
        self.logger.info(f"Saving results to {filename}")
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            self.logger.info(f"Results successfully saved to {filename}")
        except Exception as e:
            self.logger.error(f"Error saving results to {filename}: {e}")

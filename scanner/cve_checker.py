import requests
import logging

class CVEChecker:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def analyze_results(self, ports):
        vulnerabilities = []
        for port in ports:
            service = port.get("service", {}).get("name", "").strip()
            version = port.get("service", {}).get("version", "").strip()

            if not service:
                logging.warning("Skipping port due to missing service name.")
                continue

            query = f"{service}"
            if version:
                query += f"+{version}"

            try:
                url = f"{self.base_url}?keyword={query}&apiKey={self.api_key}"
                logging.info(f"Querying NVD API for service: {service}, version: {version}")
                response = requests.get(url)
                response.raise_for_status()
                data = response.json()
                if "result" in data and "CVE_Items" in data["result"]:
                    vulnerabilities.extend(data["result"]["CVE_Items"])
                else:
                    logging.warning(f"No CVEs found for {query}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error fetching CVEs: {e}")
        
        return vulnerabilities

import logging
import nmap

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("scanner.log"),
        logging.StreamHandler()
    ]
)

class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_host(self, host: str, ports: str = "1-65535", detect_os: bool = False, udp: bool = False, firewall_detection: bool = False, script: str = None) -> dict:
        try:
            print(f"Starting scanning on {host} on ports {ports}...")
            arguments = "-sV"
            if detect_os:
                arguments += " -O"
            if udp:
                arguments += " -sU"
            if firewall_detection:
                arguments += " --reason"
            if script:
                arguments += f" --script={script}"
            
            self.nm.scan(hosts=host, ports=ports, arguments=arguments)

            if not self.nm.all_hosts():
                logging.error("No hosts found. Ensure the target is reachable.")
                return {}

            return self._parse_results(host)

        except nmap.PortScannerError as e:
            logging.error(f"Error running Nmap: {e}")
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
        return {}

    def _parse_results(self, host: str) -> dict:
        results = {}
        if host in self.nm.all_hosts():
            results['host'] = host
            results['status'] = self.nm[host].state()
            results['ports'] = []

            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in sorted(ports):
                    port_info = {
                        'port': port,
                        'state': self.nm[host][proto][port]['state'],
                        'name': self.nm[host][proto][port]['name'],
                        'product': self.nm[host][proto][port].get('product', 'N/A'),
                        'version': self.nm[host][proto][port].get('version', 'N/A'),
                    }
                    results['ports'].append(port_info)

            if 'osmatch' in self.nm[host]:
                results['os'] = [
                    {
                        'name': osmatch['name'],
                        'accuracy': osmatch['accuracy'],
                        'type': osmatch.get('osclass', [{}])[0].get('type', 'N/A'),
                    }
                    for osmatch in self.nm[host]['osmatch']
                ]
        return results

    def has_admin_privileges(self) -> bool:
        import os
        return os.geteuid() == 0

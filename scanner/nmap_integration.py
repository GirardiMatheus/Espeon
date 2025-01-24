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

  def scan_host(self, host: str, ports: str = "1-65535") -> dict:

    try: 
      print(f"Starting scanning on {host} on ports {ports}...")
      self.nm.scan(hosts=host, ports=ports, arguments="-sV")
      return self._parse_results(host)

    except nmap.PortScannerError as e:
      print(f"Error running Nmap: {e}")
    except Exception as e:
      print(f"Unexpected error: {e}")
    return{}

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

    return results   


if __name__ == "__main__":
    scanner = NmapScanner()
    host_to_scan = input("Enter the host to be scanned (IP or hostname): ")
    ports_to_scan = input("Enter the range of ports to scan (default 1-65535): ") or "1-65535"

    results = scanner.scan_host(host_to_scan, ports_to_scan)
    if results:
        print("\nScan Results: ")
        print(results)
    else:
        print("\nNo results found or error when scanning.")
import logging
import nmap
import os
from typing import Dict, Optional

class NmapScanner:
    """
    Class responsible for integrating and running scans with Nmap.
    """
    def __init__(self):
        self.nm = nmap.PortScanner()
        self._setup_logging()

    def _setup_logging(self):
        """Configure logging for the scanner"""
        log_path = os.path.join(os.path.dirname(__file__), "scanner.log")
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        # Avoid adding multiple handlers if they already exist
        if not logger.handlers:
            file_handler = logging.FileHandler(log_path)
            file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
            logger.addHandler(file_handler)
            logger.addHandler(stream_handler)
        self.logger = logger

    def scan_host(self, host: str, ports: str = "1-65535", detect_os: bool = False, 
                  udp: bool = False, firewall_detection: bool = False, 
                  script: Optional[str] = None, extra_args: Optional[str] = None) -> Dict:
        """
        Perform comprehensive host scanning
        
        Args:
            host: Target host (IP or hostname)
            ports: Port range to scan
            detect_os: Enable OS detection
            udp: Enable UDP scanning  
            firewall_detection: Enable firewall detection
            script: Custom nmap script
            extra_args: Extra arguments for nmap
            
        Returns:
            Dictionary with scan results
        """
        try:
            self.logger.info(f"Starting scan on {host} (ports: {ports})")
            
            # Validate host
            if not self._validate_host(host):
                self.logger.error(f"Invalid host: {host}")
                return {}
            
            arguments = self._build_arguments(detect_os, udp, firewall_detection, script, extra_args)
            
            self.nm.scan(hosts=host, ports=ports, arguments=arguments)
            all_hosts = self.nm.all_hosts()
            if not all_hosts:
                self.logger.error("No hosts found. Target may be unreachable or filtered.")
                return {}
            scan_host = all_hosts[0]
            results = self._parse_results(scan_host)
            self.logger.info(f"Scan completed. Found {len(results.get('ports', []))} open ports.")
            return results
            
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap scanning error: {e}")
            return {}
        except Exception as e:
            self.logger.error(f"Unexpected scanning error: {e}")
            return {}

    def _validate_host(self, host: str) -> bool:
        """Validates if the host is a valid IP or hostname."""
        import re
        if not host or len(host.strip()) == 0:
            return False
        ip_regex = r"^\d{1,3}(\.\d{1,3}){3}$"
        hostname_regex = r"^[a-zA-Z0-9.-]+$"
        return re.match(ip_regex, host) or re.match(hostname_regex, host)

    def _build_arguments(self, detect_os: bool, udp: bool, 
                        firewall_detection: bool, script: Optional[str], extra_args: Optional[str]=None) -> str:
        """Build nmap command arguments"""
        arguments = ["-sV"]
        if self.has_admin_privileges():
            arguments.append("-sS")  # SYN scan (root)
        else:
            arguments.append("-sT")  # TCP connect scan (user)

        if detect_os and self.has_admin_privileges():
            arguments.append("-O")
        elif detect_os:
            self.logger.warning("OS detection requires root privileges")
            
        if udp:
            arguments.append("-sU")
            arguments.append("--top-ports 100")  # Limit UDP scan
            
        if firewall_detection:
            arguments.extend(["--reason", "-f"])  # Fragment packets
            
        if script and script.strip():
            arguments.append(f"--script={script.strip()}")
            
        # Performance optimizations
        arguments.extend(["-T4", "--min-rate=1000"])
        
        if extra_args:
            arguments.extend(extra_args.split())
        self.logger.debug(f"Nmap arguments: {' '.join(arguments)}")
        return " ".join(arguments)

    def _parse_results(self, host: str) -> Dict:
        """Parse nmap scan results"""
        results = {
            'host': host,
            'status': self.nm[host].state() if host in self.nm.all_hosts() else "unknown",
            'ports': [],
            'os': []
        }
        
        # Parse port information
        for proto in self.nm[host].all_protocols():
            ports = self.nm[host][proto].keys()
            for port in sorted(ports):
                port_data = self.nm[host][proto][port]
                
                port_info = {
                    'port': port,
                    'protocol': proto,
                    'state': port_data['state'],
                    'name': port_data['name'],
                    'product': port_data.get('product', 'N/A'),
                    'version': port_data.get('version', 'N/A'),
                    'extrainfo': port_data.get('extrainfo', 'N/A'),
                    'reason': port_data.get('reason', 'N/A'),
                    'confidence': port_data.get('conf', 'N/A')
                }
                
                # Add script results if available
                if 'script' in port_data:
                    port_info['scripts'] = []
                    for script_name, script_output in port_data['script'].items():
                        port_info['scripts'].append({
                            'id': script_name,
                            'output': script_output
                        })
                
                results['ports'].append(port_info)
        
        # Parse OS information  
        if 'osmatch' in self.nm[host]:
            for osmatch in self.nm[host]['osmatch']:
                os_info = {
                    'name': osmatch['name'],
                    'accuracy': osmatch['accuracy'],
                    'line': osmatch['line']
                }
                
                if 'osclass' in osmatch:
                    os_info['osclass'] = []
                    for osclass in osmatch['osclass']:
                        os_info['osclass'].append({
                            'type': osclass.get('type', 'N/A'),
                            'vendor': osclass.get('vendor', 'N/A'),
                            'osfamily': osclass.get('osfamily', 'N/A'),
                            'osgen': osclass.get('osgen', 'N/A'),
                            'accuracy': osclass.get('accuracy', 'N/A')
                        })
                
                results['os'].append(os_info)
        
        return results

    def has_admin_privileges(self) -> bool:
        """Check if running with administrative privileges"""
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:  # Unix/Linux
                return os.geteuid() == 0
        except:
            return False
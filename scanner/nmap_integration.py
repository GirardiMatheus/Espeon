import nmap
import os
from typing import Dict, Optional
from utils.logger_config import configure_logging, get_logger

class NmapScanner:
    """
    Class responsible for integrating and running scans with Nmap.
    """
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.logger = get_logger(__name__)
        self.logger.debug("NmapScanner initialized")

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
            self.logger.debug(f"Scan parameters - detect_os: {detect_os}, udp: {udp}, firewall_detection: {firewall_detection}")
            
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
        self.logger.debug(f"Validating host: {host}")
        import re
        if not host or len(host.strip()) == 0:
            return False
        ip_regex = r"^\d{1,3}(\.\d{1,3}){3}$"
        hostname_regex = r"^[a-zA-Z0-9.-]+$"
        is_valid = re.match(ip_regex, host) or re.match(hostname_regex, host)
        self.logger.debug(f"Host validation result for {host}: {is_valid}")
        return is_valid

    def _build_arguments(self, detect_os: bool, udp: bool, 
                        firewall_detection: bool, script: Optional[str], extra_args: Optional[str]=None) -> str:
        """Build nmap command arguments"""
        self.logger.debug("Building nmap arguments")
        arguments = ["-sV"]
        if self.has_admin_privileges():
            arguments.append("-sS")  # SYN scan (root)
            self.logger.debug("Using SYN scan (admin privileges detected)")
        else:
            arguments.append("-sT")  # TCP connect scan (user)
            self.logger.debug("Using TCP connect scan (no admin privileges)")

        if detect_os and self.has_admin_privileges():
            arguments.append("-O")
            self.logger.debug("OS detection enabled")
        elif detect_os:
            self.logger.warning("OS detection requires root privileges")
            
        if udp:
            arguments.append("-sU")
            arguments.append("--top-ports 100")  # Limit UDP scan
            self.logger.debug("UDP scanning enabled (limited to top 100 ports)")
            
        if firewall_detection:
            arguments.extend(["--reason", "-f"])  # Fragment packets
            self.logger.debug("Firewall detection enabled")
            
        if script and script.strip():
            arguments.append(f"--script={script.strip()}")
            self.logger.debug(f"Custom script enabled: {script.strip()}")
            
        # Performance optimizations
        arguments.extend(["-T4", "--min-rate=1000"])
        
        if extra_args:
            arguments.extend(extra_args.split())
            self.logger.debug(f"Extra arguments added: {extra_args}")
            
        self.logger.debug(f"Final nmap arguments: {' '.join(arguments)}")
        return " ".join(arguments)

    def _parse_results(self, host: str) -> Dict:
        """Parse nmap scan results"""
        self.logger.debug(f"Parsing scan results for host: {host}")
        results = {
            'host': host,
            'status': self.nm[host].state() if host in self.nm.all_hosts() else "unknown",
            'ports': [],
            'os': []
        }
        
        # Parse port information
        for proto in self.nm[host].all_protocols():
            self.logger.debug(f"Processing protocol: {proto}")
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
            self.logger.debug(f"Processing OS information for {host}")
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
        
        self.logger.debug(f"Parsed {len(results['ports'])} ports and {len(results['os'])} OS matches")
        return results

    def has_admin_privileges(self) -> bool:
        """Check if running with administrative privileges"""
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:  # Unix/Linux
                return os.geteuid() == 0
        except Exception as e:
            self.logger.debug(f"Error checking admin privileges: {e}")
            return False

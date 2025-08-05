import json
import csv
from utils.logger_config import configure_logging, get_logger

class ReportGenerator:
    """
    Class responsible for generating reports in different formats.
    """
    def __init__(self):
        self.logger = get_logger(__name__)
        self.logger.debug("ReportGenerator initialized")
        self._init_security_knowledge_base()
    
    def _init_security_knowledge_base(self):
        """Initialize comprehensive security knowledge base"""
        self.security_db = {
            # Web services
            "http": {
                "default_risk": "MEDIUM",
                "description": "HTTP service detected - potential for web vulnerabilities",
                "recommendations": [
                    "Ensure HTTPS is available and enforced",
                    "Implement proper input validation",
                    "Use security headers (HSTS, CSP, etc.)",
                    "Keep web server updated"
                ],
                "products": {
                    "apache": {"risk": "MEDIUM", "check_versions": ["2.2", "2.4.0-2.4.25"]},
                    "nginx": {"risk": "LOW", "check_versions": ["1.0", "1.10.0-1.10.3"]},
                    "iis": {"risk": "MEDIUM", "check_versions": ["6.0", "7.0", "7.5"]},
                    "tornado": {"risk": "HIGH", "check_versions": ["3.0", "4.0", "4.1", "4.2"]}
                }
            },
            "https": {
                "default_risk": "LOW",
                "description": "HTTPS service - generally secure but requires proper configuration",
                "recommendations": [
                    "Verify SSL/TLS configuration",
                    "Use strong cipher suites",
                    "Implement HSTS",
                    "Check certificate validity"
                ]
            },
            # Database services
            "mysql": {
                "default_risk": "HIGH",
                "description": "MySQL database service exposed",
                "recommendations": [
                    "Restrict database access to trusted IPs only",
                    "Use strong authentication",
                    "Enable SSL/TLS for connections",
                    "Regular security updates"
                ],
                "products": {
                    "mysql": {"risk": "HIGH", "check_versions": ["5.0", "5.1", "5.5", "5.6.0-5.6.25"]}
                }
            },
            "postgresql": {
                "default_risk": "HIGH",
                "description": "PostgreSQL database service exposed",
                "recommendations": [
                    "Configure pg_hba.conf properly",
                    "Use SSL connections",
                    "Implement role-based access control",
                    "Regular security patches"
                ],
                "products": {
                    "postgresql": {"risk": "HIGH", "check_versions": ["9.0", "9.1", "9.2", "9.3", "9.4", "9.5", "9.6"]}
                }
            },
            "mongodb": {
                "default_risk": "CRITICAL",
                "description": "MongoDB service exposed - high risk if not properly secured",
                "recommendations": [
                    "Enable authentication immediately",
                    "Bind to localhost only if possible",
                    "Use SSL/TLS connections",
                    "Implement role-based access control"
                ]
            },
            # Remote access services
            "ssh": {
                "default_risk": "MEDIUM",
                "description": "SSH service - secure but attractive to attackers",
                "recommendations": [
                    "Use key-based authentication",
                    "Disable root login",
                    "Change default port",
                    "Implement fail2ban or similar"
                ],
                "products": {
                    "openssh": {"risk": "MEDIUM", "check_versions": ["6.0", "6.1", "6.2", "7.0"]}
                }
            },
            "telnet": {
                "default_risk": "CRITICAL",
                "description": "Telnet service - unencrypted and highly insecure",
                "recommendations": [
                    "Disable Telnet immediately",
                    "Replace with SSH",
                    "If must use, restrict to internal network only"
                ]
            },
            "ftp": {
                "default_risk": "HIGH",
                "description": "FTP service - often insecure",
                "recommendations": [
                    "Replace with SFTP or FTPS",
                    "If must use, enable passive mode",
                    "Restrict access by IP",
                    "Use strong authentication"
                ]
            },
            # Common high-risk ports
            "3389": {  # RDP port number
                "default_risk": "HIGH",
                "description": "Remote Desktop Protocol detected",
                "recommendations": [
                    "Use VPN for remote access",
                    "Enable Network Level Authentication",
                    "Use strong passwords or certificates",
                    "Restrict access by IP"
                ]
            }
        }

    def analyze_security(self, results, include_generic: bool = True):
        """
        Enhanced security analysis with comprehensive knowledge base and CVE integration.
        :param results: Dictionary of scan results.
        :param include_generic: If True, includes generic recommendations.
        """
        self.logger.info("Starting enhanced security analysis")
        self.logger.debug(f"Analysis parameters - include_generic: {include_generic}")
        
        analysis = {}
        ports = results.get("ports", [])
        vulnerabilities = results.get("vulnerabilities", {})
        
        self.logger.debug(f"Analyzing {len(ports)} ports for security issues")
        
        for port_info in ports:
            port = port_info.get("port")
            name = port_info.get("name", "unknown")
            product = port_info.get("product", "unknown").lower()
            version = port_info.get("version", "unknown")
            state = port_info.get("state", "unknown")
            
            if not name or state != "open":
                continue
            
            # Get CVE count for this service
            service_key = f"{name}_{port}"
            cve_count = len(vulnerabilities.get(service_key, []))
            cve_severities = [cve.get("severity", "UNKNOWN") for cve in vulnerabilities.get(service_key, [])]
            
            # Analyze based on service name or port
            risk_info = self._analyze_service_risk(name, product, version, port, cve_count, cve_severities)
            
            if risk_info:
                analysis[port] = risk_info
            elif include_generic:
                analysis[port] = {
                    "risk_level": "LOW",
                    "description": f"Service {name} on port {port} appears to be running normally",
                    "recommendations": ["Monitor for unusual activity", "Keep service updated"],
                    "cve_context": f"{cve_count} CVEs found" if cve_count > 0 else "No CVEs found"
                }

        self.logger.info(f"Enhanced security analysis completed. Found {len(analysis)} items to analyze")
        self.logger.debug(f"Security analysis results: {analysis}")
        return analysis

    def _analyze_service_risk(self, service_name, product, version, port, cve_count, cve_severities):
        """
        Analyze risk for a specific service with CVE context.
        """
        # Check by service name first
        service_info = self.security_db.get(service_name.lower())
        if not service_info:
            # Check by port number for well-known services
            service_info = self.security_db.get(str(port))
        
        if not service_info:
            # Unknown service - base analysis on CVEs
            if cve_count > 0:
                risk_level = self._calculate_cve_risk(cve_severities)
                return {
                    "risk_level": risk_level,
                    "description": f"Unknown service {service_name} with {cve_count} known vulnerabilities",
                    "recommendations": ["Identify service purpose", "Apply security patches", "Consider disabling if unnecessary"],
                    "cve_context": f"{cve_count} CVEs found: {', '.join(set(cve_severities))}"
                }
            return None

        # Base risk from knowledge base
        base_risk = service_info.get("default_risk", "MEDIUM")
        description = service_info.get("description", f"{service_name} service detected")
        recommendations = service_info.get("recommendations", [])

        # Check for specific product vulnerabilities
        if product and product != "unknown":
            product_info = service_info.get("products", {}).get(product.lower(), {})
            if product_info:
                product_risk = product_info.get("risk", base_risk)
                check_versions = product_info.get("check_versions", [])
                
                # Check if version is in vulnerable list
                if version and version != "unknown":
                    for vuln_version in check_versions:
                        if version.startswith(vuln_version):
                            base_risk = "HIGH"
                            description += f" - Potentially vulnerable {product} {version}"
                            break

        # Adjust risk based on CVE findings
        if cve_count > 0:
            cve_risk = self._calculate_cve_risk(cve_severities)
            # Take the higher risk between base and CVE analysis
            final_risk = self._max_risk(base_risk, cve_risk)
            cve_context = f"{cve_count} CVEs found: {', '.join(set(cve_severities))}"
        else:
            final_risk = base_risk
            cve_context = "No CVEs found"

        return {
            "risk_level": final_risk,
            "description": description,
            "recommendations": recommendations,
            "cve_context": cve_context,
            "product_info": f"{product} {version}" if product != "unknown" else "Unknown product"
        }

    def _calculate_cve_risk(self, severities):
        """Calculate risk level based on CVE severities"""
        if "CRITICAL" in severities:
            return "CRITICAL"
        elif "HIGH" in severities:
            return "HIGH"
        elif "MEDIUM" in severities:
            return "MEDIUM"
        elif "LOW" in severities:
            return "LOW"
        else:
            return "MEDIUM"  # Default for unknown severities

    def _max_risk(self, risk1, risk2):
        """Return the higher risk level between two risks"""
        risk_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        level1 = risk_levels.get(risk1, 2)
        level2 = risk_levels.get(risk2, 2)
        
        for risk, level in risk_levels.items():
            if level == max(level1, level2):
                return risk
        return "MEDIUM"

    def generate_text_report(self, results: dict, include_security: bool = True) -> str:
        """
        Generates a text report with enhanced security analysis.
        """
        self.logger.info("Generating text report")
        self.logger.debug(f"Report parameters - include_security: {include_security}")
        
        try:
            report = []
            report.append(f"Host: {results['host']}")
            report.append(f"Status: {results['status']}")
            report.append("Ports:")
            
            for port in results.get("ports", []):
                report.append(
                    f"  Port: {port['port']}, State: {port['state']}, "
                    f"Name: {port['name']}, Product: {port['product']}, Version: {port['version']}"
                )
                
                if port.get("protocol") == "udp":
                    report.append("    - Protocol: UDP (may be filtered or blocked)")

                if port.get("reason"):
                    report.append(f"    - Response reason: {port['reason']}")

                if "scripts" in port:
                    report.append("    - Executed scripts:")
                    for script in port["scripts"]:
                        report.append(f"      - {script['id']}: {script['output']}")

            if 'os' in results:
                report.append("OS Detection:")
                for os in results['os']:
                    report.append(
                        f"  Name: {os['name']}, Accuracy: {os['accuracy']}, Type: {os.get('type', 'N/A')}"
                    )

            # Enhanced security analysis section
            if include_security:
                has_security_data = False
                security_section = ["\n# Security Analysis"]
                
                # Add enhanced security analysis if available
                if 'security_analysis' in results and results['security_analysis']:
                    security_section.append("## Risk Assessment:")
                    for port, analysis in results['security_analysis'].items():
                        if isinstance(analysis, dict):
                            risk_level = analysis.get('risk_level', 'UNKNOWN')
                            description = analysis.get('description', 'No description')
                            cve_context = analysis.get('cve_context', 'No CVE information')
                            product_info = analysis.get('product_info', 'Unknown product')
                            
                            security_section.append(f"  Port {port} [{risk_level} RISK]:")
                            security_section.append(f"    Description: {description}")
                            security_section.append(f"    Product: {product_info}")
                            security_section.append(f"    CVE Status: {cve_context}")
                            
                            recommendations = analysis.get('recommendations', [])
                            if recommendations:
                                security_section.append("    Recommendations:")
                                for rec in recommendations:
                                    security_section.append(f"      - {rec}")
                        else:
                            # Fallback for old format
                            security_section.append(f"  Port {port}: {analysis}")
                    has_security_data = True

                # Add CVE vulnerabilities if available
                if 'vulnerabilities' in results and results['vulnerabilities']:
                    if has_security_data:
                        security_section.append("")  # Add spacing
                    security_section.append("## Detected Vulnerabilities:")
                    for service, cves in results["vulnerabilities"].items():
                        security_section.append(f"  Service: {service}")
                        if cves:
                            for cve in cves:
                                security_section.append(
                                    f"    - CVE ID: {cve['id']}, Severity: {cve['severity']}, "
                                    f"Description: {cve['description']}"
                                )
                        else:
                            security_section.append("    - No CVEs found for this service.")

                    security_section.append("\n## Mitigation Suggestions:")
                    for service, cves in results["vulnerabilities"].items():
                        if cves:  # Only show suggestions for services with actual CVEs
                            security_section.append(f"  Service: {service}")
                            security_section.append("    - Apply the latest available patches or updates.")
                            security_section.append("    - Restrict access to the service to trusted IPs, if possible.")
                            security_section.append("    - Use strong authentication and properly configure firewalls.")
                    has_security_data = True

                # Only add security section if there's actual security data
                if has_security_data:
                    report.extend(security_section)

            self.logger.info("Text report generated successfully")
            self.logger.debug(f"Report length: {len(report)} lines")
            return "\n".join(report)
        except Exception as e:
            self.logger.error(f"Failed to generate text report: {e}")
            raise RuntimeError(f"Failed to generate text report: {e}")

    def generate_json_report(self, results: dict, output_file: str, encoding: str = "utf-8") -> None:
        """
        Generates a report in JSON format.
        :param results: Dictionary of results.
        :param output_file: Output file path.
        :param encoding: Output file encoding.
        """
        self.logger.info(f"Generating JSON report to {output_file}")
        self.logger.debug(f"JSON report parameters - encoding: {encoding}")
        
        try:
            with open(output_file, "w", encoding=encoding) as f:
                json.dump(results, f, indent=4)
            self.logger.info(f"JSON report successfully saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {e}")
            raise RuntimeError(f"Failed to generate JSON report: {e}")

    def generate_csv_report(self, results: dict, output_file: str, encoding: str = "utf-8") -> None:
        """
        Generates a report in CSV format.
        :param results: Dictionary of results.
        :param output_file: Output file path.
        :param encoding: Output file encoding.
        """
        self.logger.info(f"Generating CSV report to {output_file}")
        self.logger.debug(f"CSV report parameters - encoding: {encoding}")
        
        try:
            with open(output_file, "w", newline="", encoding=encoding) as f:
                writer = csv.writer(f)
                writer.writerow(["Port", "State", "Name", "Product", "Version", "Protocol", "Firewall Reason", "Scripts"])
                for port in results.get("ports", []):
                    script_data = "; ".join(
                        [f"{script['id']}: {script['output']}" for script in port.get("scripts", [])]
                    )
                    writer.writerow([
                        port["port"],
                        port["state"],
                        port["name"],
                        port["product"],
                        port["version"],
                        port.get("protocol", "N/A"),
                        port.get("reason", "N/A"),
                        script_data
                    ])
                if 'vulnerabilities' in results and results['vulnerabilities']:
                    writer.writerow([])
                    writer.writerow(["Service", "CVE ID", "Description", "Severity"])
                    for service, cves in results["vulnerabilities"].items():
                        for cve in cves:
                            writer.writerow([service, cve["id"], cve["description"], cve["severity"]])
            self.logger.info(f"CSV report successfully saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to generate CSV report: {e}")
            raise RuntimeError(f"Failed to generate CSV report: {e}")

import json
import csv

class ReportGenerator:
    """
    Class responsible for generating reports in different formats.
    """
    def __init__(self):
        pass
    
    def analyze_security(self, results, include_generic: bool = True):
        """
        Analyzes the results and suggests security recommendations.
        :param results: Dictionary of scan results.
        :param include_generic: If True, includes generic recommendations.
        """
        analysis = {}
        ports = results.get("ports", [])
        
        for port_info in ports:
            port = port_info.get("port")
            name = port_info.get("name", "unknown")
            product = port_info.get("product", "unknown")
            version = port_info.get("version", "unknown")
            
            if not name:
                continue  
            

            if name == "http" and "Tornado" in product:
                analysis[port] = f"Outdated web server detected: {product} {version}. Consider updating."
            elif name == "postgresql" and version.startswith("9.6"):
                analysis[port] = f"Potential outdated PostgreSQL version detected: {version}. Consider upgrading."
            elif name == "mongod":
                analysis[port] = "MongoDB detected. Ensure authentication is enabled."
            if include_generic and port not in analysis:
                analysis[port] = f"No specific issues identified for {name} ({product} {version})."

        return analysis
    def generate_text_report(self, results: dict, include_security: bool = True) -> str:
        """
        Generates a text report.
        :param results: Dictionary of results.
        :param include_security: If True, includes security analysis.
        """
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
                        f"  Name: {os['name']}, Accuracy: {os['accuracy']}, Type: {os['type']}"
                    )

            if include_security and 'security_analysis' in results:
                report.append("\n# Security Analysis")
                for port, msg in results['security_analysis'].items():
                    report.append(f"  Port {port}: {msg}")

            if 'vulnerabilities' in results and results['vulnerabilities']:
                report.append("\n# Security Analysis")
                report.append("## Detected Risks:")
                for service, cves in results["vulnerabilities"].items():
                    report.append(f"  Service: {service}")
                    if cves:
                        for cve in cves:
                            report.append(
                                f"    - CVE ID: {cve['id']}, Severity: {cve['severity']}, "
                                f"Description: {cve['description']}"
                            )
                    else:
                        report.append("    - No CVEs found for this service.")

                report.append("\n## Mitigation Suggestions:")
                for service, cves in results["vulnerabilities"].items():
                    report.append(f"  Service: {service}")
                    report.append("    - Apply the latest available patches or updates.")
                    report.append("    - Restrict access to the service to trusted IPs, if possible.")
                    report.append("    - Use strong authentication and properly configure firewalls.")

            return "\n".join(report)
        except Exception as e:
            raise RuntimeError(f"Failed to generate text report: {e}")

    def generate_json_report(self, results: dict, output_file: str, encoding: str = "utf-8") -> None:
        """
        Generates a report in JSON format.
        :param results: Dictionary of results.
        :param output_file: Output file path.
        :param encoding: Output file encoding.
        """
        try:
            with open(output_file, "w", encoding=encoding) as f:
                json.dump(results, f, indent=4)
        except Exception as e:
            raise RuntimeError(f"Failed to generate JSON report: {e}")

    def generate_csv_report(self, results: dict, output_file: str, encoding: str = "utf-8") -> None:
        """
        Generates a report in CSV format.
        :param results: Dictionary of results.
        :param output_file: Output file path.
        :param encoding: Output file encoding.
        """
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
        except Exception as e:
            raise RuntimeError(f"Failed to generate CSV report: {e}")

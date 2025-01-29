import json
import csv

class ReportGenerator:
    def __init__(self):
        pass
    
    def analyze_security(self, results):
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
            else:
                analysis[port] = f"No specific issues identified for {name} ({product} {version})."

        return analysis
    def generate_text_report(self, results: dict) -> str:
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
                    report.append("    - Protocolo: UDP (pode ser filtrado ou bloqueado)")

                if port.get("reason"):
                    report.append(f"    - Motivo da resposta: {port['reason']}")

                if "scripts" in port:
                    report.append("    - Scripts executados:")
                    for script in port["scripts"]:
                        report.append(f"      - {script['id']}: {script['output']}")

            if 'os' in results:
                report.append("OS Detection:")
                for os in results['os']:
                    report.append(
                        f"  Name: {os['name']}, Accuracy: {os['accuracy']}, Type: {os['type']}"
                    )

            if 'vulnerabilities' in results and results['vulnerabilities']:
                report.append("\n# Análise de Segurança")
                report.append("## Riscos Detectados:")
                for service, cves in results["vulnerabilities"].items():
                    report.append(f"  Serviço: {service}")
                    for cve in cves:
                        report.append(
                            f"    - CVE ID: {cve['id']}, Severidade: {cve['severity']}, "
                            f"Descrição: {cve['description']}"
                        )

                report.append("\n## Sugestões de Mitigação:")
                for service, cves in results["vulnerabilities"].items():
                    report.append(f"  Serviço: {service}")
                    report.append("    - Aplique patches ou atualizações mais recentes disponíveis.")
                    report.append("    - Restrinja o acesso ao serviço a IPs confiáveis, se possível.")
                    report.append("    - Use autenticação forte e configure firewalls adequadamente.")

            return "\n".join(report)
        except Exception as e:
            raise RuntimeError(f"Failed to generate text report: {e}")

    def generate_json_report(self, results: dict, output_file: str) -> None:
        try:
            with open(output_file, "w") as f:
                json.dump(results, f, indent=4)
        except Exception as e:
            raise RuntimeError(f"Failed to generate JSON report: {e}")

    def generate_csv_report(self, results: dict, output_file: str) -> None:
        try:
            with open(output_file, "w", newline="") as f:
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

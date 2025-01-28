import argparse
import os
from dotenv import load_dotenv
from scanner.nmap_integration import NmapScanner
from scanner.report_generator import ReportGenerator
from scanner.cve_checker import CVEChecker

def main():
    load_dotenv()
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        print("API key for NVD is missing. Please set it in the .env file.")
        return

    parser = argparse.ArgumentParser(description="Nmap Vulnerability Scanner")
    parser.add_argument("--host", required=True, help="Host to scan (IP or hostname)")
    parser.add_argument("--ports", default="1-65535", help="Range of ports to scan (default: 1-65535)")
    parser.add_argument("--os-detection", action="store_true", help="Enable OS detection (requires root)")
    parser.add_argument("--output", choices=["json", "txt", "csv"], default="txt", help="Output format (default: txt)")
    args = parser.parse_args()

    scanner = NmapScanner()
    report_gen = ReportGenerator()
    cve_checker = CVEChecker(api_key=api_key)

    if args.os_detection and not scanner.has_admin_privileges():
        print("OS detection requires administrative privileges. Please run as root.")
        return

    print(f"Scanning host {args.host} on ports {args.ports}...")
    results = scanner.scan_host(args.host, args.ports, args.os_detection)

    if results:
        print("Analyzing vulnerabilities...")
        vulnerabilities = cve_checker.analyze_results(results.get("ports", []))
        results["vulnerabilities"] = vulnerabilities

        print("Performing security analysis...")
        security_analysis = report_gen.analyze_security(results)
        results["security_analysis"] = security_analysis

        try:
            if args.output == "txt":
                report = report_gen.generate_text_report(results)
                with open("scan_report.txt", "w") as f:
                    f.write(report)
                print("Text report generated at scan_report.txt")
            elif args.output == "json":
                report_gen.generate_json_report(results, "scan_report.json")
                print("JSON report generated at scan_report.json")
            elif args.output == "csv":
                report_gen.generate_csv_report(results, "scan_report.csv")
                print("CSV report generated at scan_report.csv")
        except RuntimeError as e:
            print(f"Error generating report: {e}")
    else:
        print("Scan failed or returned no results.")

if __name__ == "__main__":
    main()

import argparse
import os
import json
import threading
import sys
import time
import logging
from dotenv import load_dotenv
from scanner.nmap_integration import NmapScanner
from scanner.report_generator import ReportGenerator
from scanner.cve_checker import CVEChecker

def load_config():
    config_path = "config.json"
    if os.path.exists(config_path):
        with open(config_path, "r") as file:
            return json.load(file)
    return {}

def spinner(msg, stop_event):
    import itertools
    for c in itertools.cycle('|/-\\'):
        if stop_event.is_set():
            break
        sys.stdout.write(f'\r{msg} {c}')
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * (len(msg) + 2) + '\r')

def main():
    load_dotenv()
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        print("Aviso: API key do NVD não encontrada. A verificação de CVEs pode ser limitada.")

    config = load_config()

    parser = argparse.ArgumentParser(description="Nmap Vulnerability Scanner")
    parser.add_argument("--host", required=True, help="Host to scan (IP or hostname)")
    parser.add_argument("--ports", default=config.get("default_ports", "1-65535"), help="Range of ports to scan")
    parser.add_argument("--os-detection", action="store_true", help="Enable OS detection (requires root)")
    parser.add_argument("--udp", action="store_true", default=config.get("enable_udp_scan", False), help="Enable UDP scanning")
    parser.add_argument("--firewall", action="store_true", default=config.get("enable_firewall_detection", False), help="Enable firewall detection")
    parser.add_argument("--script", default=config.get("custom_nmap_scripts", ""), help="Specify an Nmap script for scanning")
    parser.add_argument("--output", choices=["json", "txt", "csv"], default="txt", help="Output format (default: txt)")
    parser.add_argument("--output-file", default=None, help="Nome do arquivo de saída (opcional)")
    parser.add_argument("--verbose", action="store_true", help="Ativa logging detalhado")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    scanner = NmapScanner()
    report_gen = ReportGenerator()
    cve_checker = CVEChecker(api_key=api_key)

    if args.os_detection and not scanner.has_admin_privileges():
        print("OS detection requires administrative privileges. Please run as root.")
        return

    print(f"Scanning host {args.host} on ports {args.ports}...")

    # Inicia spinner
    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=spinner, args=("Scanning in progress", stop_event))
    spinner_thread.start()

    try:
        results = scanner.scan_host(args.host, args.ports, args.os_detection, args.udp, args.firewall, args.script)
    finally:
        stop_event.set()
        spinner_thread.join()

    if results:
        print("Analyzing vulnerabilities...")
        vulnerabilities = cve_checker.analyze_results(results.get("ports", []))
        results["vulnerabilities"] = vulnerabilities

        print("Performing security analysis...")
        security_analysis = report_gen.analyze_security(results)
        results["security_analysis"] = security_analysis

        try:
            output_file = args.output_file
            if args.output == "txt":
                report = report_gen.generate_text_report(results)
                output_file = output_file or "scan_report.txt"
                with open(output_file, "w") as f:
                    f.write(report)
                print(f"Text report generated at {output_file}")
            elif args.output == "json":
                output_file = output_file or "scan_report.json"
                report_gen.generate_json_report(results, output_file)
                print(f"JSON report generated at {output_file}")
            elif args.output == "csv":
                output_file = output_file or "scan_report.csv"
                report_gen.generate_csv_report(results, output_file)
                print(f"CSV report generated at {output_file}")
        except RuntimeError as e:
            print(f"Error generating report: {e}")
    else:
        print("Scan failed or returned no results.")

if __name__ == "__main__":
    main()

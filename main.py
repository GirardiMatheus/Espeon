import argparse
import os
import sys
import time
import itertools
import threading
import logging
import json
from dotenv import load_dotenv
from utils.logger_config import configure_logging, get_logger
from scanner.nmap_integration import NmapScanner
from scanner.cve_checker import CVEChecker
from scanner.report_generator import ReportGenerator

def load_config():
    config_path = "config.json"
    if os.path.exists(config_path):
        with open(config_path, "r") as file:
            return json.load(file)
    return {}

def spinner(msg, stop_event):
    for c in itertools.cycle('|/-\\'):
        if stop_event.is_set():
            break
        sys.stdout.write(f'\r{msg} {c}')
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * (len(msg) + 2) + '\r')

def main():
    parser = argparse.ArgumentParser(description="Espeon - Advanced Vulnerability Scanner")

    parser.add_argument("--host", required=True, help="Target host or IP address")
    parser.add_argument("--ports", help="Port range (e.g., 1-65535)")
    parser.add_argument("--os-detection", action="store_true", help="Enable OS detection")
    parser.add_argument("--udp", action="store_true", help="Enable UDP scan")
    parser.add_argument("--firewall", action="store_true", help="Enable firewall detection")
    parser.add_argument("--script", help="Custom Nmap script to run")
    parser.add_argument("--output", nargs="+", choices=["json", "csv", "txt"], default=["json"], help="Report format(s)")
    parser.add_argument("--output-file", help="Output filename without extension")
    parser.add_argument("--api-key", help="NVD API key for CVE queries")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose mode")

    args = parser.parse_args()

    # Load environment variables and config
    load_dotenv()
    config = load_config()

    # Logging setup
    log_level = logging.DEBUG if args.verbose else logging.INFO
    configure_logging(level=log_level)
    logger = get_logger(__name__)

    logger.info("=== Espeon Vulnerability Scanner Started ===")
    logger.debug(f"Arguments: {args}")

    try:
        scanner = NmapScanner()

        # Definições com fallback para config.json
        ports = args.ports or config.get("default_ports", "1-65535")
        enable_udp = args.udp or config.get("enable_udp_scan", False)
        enable_firewall = args.firewall or config.get("enable_firewall_detection", False)
        os_detection = args.os_detection
        custom_script = args.script or config.get("custom_nmap_scripts", "")

        logger.info(f"Scanning host: {args.host} | Ports: {ports}")

        stop_spinner = threading.Event()
        spinner_thread = threading.Thread(target=spinner, args=("Scanning target...", stop_spinner))
        spinner_thread.start()

        scan_results = scanner.scan_host(
            host=args.host,
            ports=ports,
            udp=enable_udp,
            detect_os=os_detection,
            firewall_detection=enable_firewall,
            script=custom_script
        )

        stop_spinner.set()
        spinner_thread.join()

        if not scan_results or "ports" not in scan_results or not isinstance(scan_results["ports"], list):
            logger.warning("No results from scan or invalid format.")
            return

        logger.info(f"Scan complete. {len(scan_results['ports'])} open ports detected.")

        api_key = args.api_key or os.getenv("NVD_API_KEY")
        if not api_key:
            logger.warning("No NVD API key provided. CVE lookups may be limited or fail.")

        cve_checker = CVEChecker(api_key=api_key)
        vulnerabilities = cve_checker.analyze_results(scan_results["ports"])

        results = {
            "host": args.host,
            "status": "completed",
            "ports": scan_results["ports"],
            "vulnerabilities": vulnerabilities
        }

        report_generator = ReportGenerator()
        results["security_analysis"] = report_generator.analyze_security(results)

        output_base = args.output_file or f"espeon_results_{args.host}"

        if "json" in args.output:
            json_file = f"{output_base}.json"
            report_generator.generate_json_report(results, json_file)
            logger.info(f"JSON report saved to: {json_file}")

        if "txt" in args.output:
            txt_file = f"{output_base}.txt"
            text_report = report_generator.generate_text_report(results)
            with open(txt_file, "w", encoding="utf-8") as f:
                f.write(text_report)
            logger.info(f"TXT report saved to: {txt_file}")

        if "csv" in args.output:
            csv_file = f"{output_base}.csv"
            report_generator.generate_csv_report(results, csv_file)
            logger.info(f"CSV report saved to: {csv_file}")

        total_cves = sum(len(v) for v in vulnerabilities.values())
        logger.info(f"Found {total_cves} potential vulnerabilities.")
        logger.info("Espeon scan complete.")

    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
    except Exception as e:
        logger.exception("An unexpected error occurred.")
        sys.exit(1)

if __name__ == "__main__":
    main()

import argparse
import os
import json
import threading
import sys
import time
import itertools
import logging
from dotenv import load_dotenv
from utils.logger_config import configure_logging, get_logger
from scanner.nmap_integration import NmapScanner
from scanner.cve_checker import CVEChecker

def load_config():
    config_path = "config.json"
    if os.path.exists(config_path):
        with open(config_path, "r") as file:
            return json.load(file)
    return {}

def spinner(msg, stop_event):
    """Displays an animated spinner in the terminal while stop_event is not set."""
    for c in itertools.cycle('|/-\\'):
        if stop_event.is_set():
            break
        sys.stdout.write(f'\r{msg} {c}')
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * (len(msg) + 2) + '\r')

def main():
    """Main scanner function."""
    parser = argparse.ArgumentParser(description="Espeon - Advanced Vulnerability Scanner")
    parser.add_argument("--host", required=True, help="Target host or IP address")
    parser.add_argument("--ports", help="Port range (e.g., 1-1000)")
    parser.add_argument("--output", help="Output file for results")
    parser.add_argument("--api-key", help="NVD API key for CVE queries")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--log-file", help="Log file path")

    args = parser.parse_args()

    # Configure logging via utils/logger_config.py
    log_level = logging.DEBUG if args.debug else logging.INFO
    configure_logging(level=log_level, log_file=args.log_file)
    logger = get_logger(__name__)

    logger.info("=== Espeon Vulnerability Scanner Started ===")
    logger.debug(f"Arguments received: {args}")
    logger.info(f"Target: {args.host}")

    try:
        scanner = NmapScanner()
        logger.info("Nmap scanner initialized successfully")

        ports = args.ports if args.ports else "1-65535"
        logger.info(f"Starting port scan on target {args.host} with port range: {ports}")

        # Spinner in thread while scan is running
        stop_spinner = threading.Event()
        spinner_thread = threading.Thread(target=spinner, args=("Scanning target...", stop_spinner))
        spinner_thread.start()

        scan_results = scanner.scan_host(args.host, ports)

        # Stop spinner after scan
        stop_spinner.set()
        spinner_thread.join()

        logger.debug(f"Raw scan_results type: {type(scan_results)}")
        logger.debug(f"Raw scan_results content: {scan_results}")

        if not scan_results:
            logger.warning("No open ports found or scan failed. Exiting...")
            return

        # Validate and normalize scan_results format
        if isinstance(scan_results, dict):
            logger.debug("Converting dict scan_results to list format")
            logger.debug(f"Dict keys: {list(scan_results.keys())}")
            # If it's a dict, extract the ports information
            if 'ports' in scan_results:
                scan_results = scan_results['ports']
                if not scan_results:  # Check if ports list is empty
                    logger.info("No open ports found on target. Exiting...")
                    return
            elif 'tcp' in scan_results:
                # Convert nmap-style dict to list format
                ports_list = []
                for port_num, port_info in scan_results['tcp'].items():
                    port_data = {
                        'port': port_num,
                        'state': port_info.get('state', 'unknown'),
                        'name': port_info.get('name', ''),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', '')
                    }
                    ports_list.append(port_data)
                scan_results = ports_list
                if not scan_results:  # Check if ports list is empty
                    logger.info("No open ports found on target. Exiting...")
                    return
            else:
                logger.warning(f"Dict scan_results has no recognizable port data. Keys: {list(scan_results.keys())}")
                logger.debug(f"scan_results content: {scan_results}")
                logger.info("No open ports found. Exiting...")
                return
        elif not isinstance(scan_results, list):
            logger.error(f"Unexpected scan_results format: {type(scan_results)}. Expected list or dict.")
            logger.debug(f"scan_results content: {scan_results}")
            return

        # Check if all items in scan_results are dictionaries
        invalid_items = [item for item in scan_results if not isinstance(item, dict)]
        if invalid_items:
            logger.error(f"Found {len(invalid_items)} invalid items in scan_results. Expected dictionaries.")
            logger.debug(f"Invalid items: {invalid_items}")
            logger.info("Filtering out invalid items and continuing...")
            scan_results = [item for item in scan_results if isinstance(item, dict)]

        if not scan_results:
            logger.warning("No valid scan results after filtering. Exiting...")
            return

        logger.info(f"Port scan completed. {len(scan_results)} open ports found.")
        logger.debug(f"Scan results: {scan_results}")

        api_key = args.api_key or os.getenv('NVD_API_KEY')
        if not api_key:
            logger.warning("No API key provided; CVE analysis may be limited or fail.")

        cve_checker = CVEChecker(api_key=api_key)
        logger.info("CVEChecker initialized")

        logger.info("Starting vulnerability analysis...")
        vulnerabilities = cve_checker.analyze_results(scan_results)
        logger.info("Vulnerability analysis completed")
        logger.debug(f"Vulnerabilities found: {vulnerabilities}")

        results = {
            "target": args.host,
            "scan_results": scan_results,
            "vulnerabilities": vulnerabilities
        }

        output_file = args.output or f"espeon_results_{args.host}.json"
        logger.info(f"Saving results to {output_file}...")
        cve_checker.save_to_json(results, output_file)

        total_cves = sum(len(cves) for cves in vulnerabilities.values())
        logger.info(f"Scan completed. {total_cves} potential vulnerabilities found.")
        logger.info(f"Results saved to: {output_file}")

    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user (KeyboardInterrupt)")
    except Exception:
        logger.exception("Unexpected error occurred during scan execution")
        sys.exit(1)

if __name__ == "__main__":
    main()

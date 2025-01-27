from scanner.nmap_integration import NmapScanner
from scanner.report_generator import ReportGenerator

def main():
    scanner = NmapScanner()
    report_gen = ReportGenerator()

    host = input("Enter the host to scan (IP or hostname): ")
    ports = input("Enter the range of ports to scan (default 1-65535): ") or "1-65535"
    detect_os = input("Enable OS detection? (yes/no, default: no): ").lower() == "yes"

    if detect_os and not scanner.has_admin_privileges():
        print("OS detection requires administrative privileges. Please run as root.")
        return

    results = scanner.scan_host(host, ports, detect_os)

    if results:
        try:
            text_report = report_gen.generate_text_report(results)
            with open("scan_report.txt", "w") as f:
                f.write(text_report)
            print("Text report generated at scan_report.txt")
        except RuntimeError as e:
            print(e)

        try:
            report_gen.generate_json_report(results, "scan_report.json")
            print("JSON report generated at scan_report.json")
        except RuntimeError as e:
            print(e)

        try:
            report_gen.generate_csv_report(results, "scan_report.csv")
            print("CSV report generated at scan_report.csv")
        except RuntimeError as e:
            print(e)
    else:
        print("Scan failed or returned no results.")

if __name__ == "__main__":
    main()
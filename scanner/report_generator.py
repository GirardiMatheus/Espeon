import json
import csv

class ReportGenerator:
    def __init__(self):
        pass

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
            if 'os' in results:
                report.append("OS Detection:")
                for os in results['os']:
                    report.append(
                        f"  Name: {os['name']}, Accuracy: {os['accuracy']}, Type: {os['type']}"
                    )
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
                writer.writerow(["Port", "State", "Name", "Product", "Version"])
                for port in results.get("ports", []):
                    writer.writerow([port["port"], port["state"], port["name"], port["product"], port["version"]])
        except Exception as e:
            raise RuntimeError(f"Failed to generate CSV report: {e}")

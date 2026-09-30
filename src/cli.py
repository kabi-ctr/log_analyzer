import argparse
import yaml
from src.parser import load_logs
from src.detector import ThreatDetector
from src.reporter import generate_firewall_rules, write_markdown_report

def main():
    parser = argparse.ArgumentParser(description="Log Analyzer & Threat Detector")
    parser.add_argument("log_file", help="Provide path to the log filr")
    parser.add_argument("--type", choices=["ssh", "web"], required=True, help="Log type")
    parser.add_argument("--config", default="config/rules.yaml", help="Path to YAML rules")
    parser.add_argument("--report", default="report.md", help="Output report file")
    parser.add_argument("--fw-syntax", choices=["iptables", "nftables"], default="nftables")
    
    args = parser.parse_args()

    with open(args.config) as f:
           config = yaml.safe_load(f)

    df, failed = load_logs(args.log_file, args.type)
    detector = ThreatDetector(config)

    if args.type == "ssh":
        alerts = detector.detect_ssh_brute_force(df)
    else:
        alerts = detector.detect_web_scanners(df)

    write_markdown_report(alerts, failed, args.report)
    
    if not alerts.empty:
        offenders = alerts["source_ip"].unique().tolist()
        print("--- Suggested Firewall Rules ---")
        print(generate_firewall_rules(offenders, args.fw_syntax))

if __name__ == "__main__":
    main()

import argparse

import yaml

from src.detector import ThreatDetector
from src.parser import load_logs
from src.reporter import generate_firewall_rules, write_markdown_report


def main():
    parser = argparse.ArgumentParser(description="Log Analyzer & Threat Detector")
    parser.add_argument("log_file", help="Path to the SSH auth log file")
    parser.add_argument("--config", default="config/rules.yaml", help="Path to YAML rules")
    parser.add_argument("--report", default="report.md", help="Output report file")
    parser.add_argument("--fw-syntax", choices=["iptables", "nftables"], default="nftables")
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    df, unparsed = load_logs(args.log_file)
    detector = ThreatDetector(config)
    alerts = detector.detect_ssh_brute_force(df)

    write_markdown_report(alerts, unparsed, args.report)

    if not alerts.empty:
        offenders = alerts["source_ip"].unique().tolist()
        print("--- Suggested Firewall Rules ---")
        print(generate_firewall_rules(offenders, args.fw_syntax))


if __name__ == "__main__":
    main()

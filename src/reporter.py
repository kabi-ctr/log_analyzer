import pandas as pd

def generate_firewall_rules(offending_ips: list[str], syntax: str = "nftables") -> str:
    rules = []
    rules.append(f"# WARNING: Suggested rules only. Inspect before executing.\n")
    for ip in offending_ips:
        if syntax == "iptables":
            rules.append(f"iptables -A INPUT -s {ip} -j DROP")
        elif syntax == "nftables":
            rules.append(f"nft add rule inet filter input ip saddr {ip} drop")
    return "\n".join(rules)

def write_markdown_report(df_alerts: pd.DataFrame, failed_lines: int, output_path: str):
    with open(output_path, "w") as f:
        f.write("# Threat Detection Report\n\n")
        f.write(f"**Unparsed Lines (Malformed):** {failed_lines}\n\n")
        f.write("## Flagged Offending IPs\n\n")
        if df_alerts.empty:
            f.write("No suspicious activities detected.\n")
        else:
            f.write(df_alerts.to_markdown(index=False))
            f.write("\n")

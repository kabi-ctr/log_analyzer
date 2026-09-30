from datetime import timedelta
import pandas as pd

class ThreatDetector:
    def __init__(self, config: dict):
        self.config = config

    def detect_ssh_brute_force(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()
        cfg = self.config["ssh_brute_force"]
        ssh_df = df[(df["event_type"] == "ssh_auth") & (df["status"] == "failed")].copy()
        
        flagged = []
        for ip, group in ssh_df.groupby("source_ip"):
            group = group.sort_values("timestamp")
            for i in range(len(group)):
                start = group.iloc[i]["timestamp"]
                end = start + timedelta(minutes=cfg["window_minutes"])
                window_count = len(group[(group["timestamp"] >= start) & (group["timestamp"] <= end)])
                if window_count >= cfg["failed_attempts"]:
                    flagged.append({"source_ip": ip, "reason": "SSH Brute Force", "count": window_count})
                    break
        return pd.DataFrame(flagged)


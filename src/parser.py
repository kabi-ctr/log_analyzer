import re
from datetime import datetime

import pandas as pd

SSH_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+'
    r'(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)'
)

def parse_ssh_line(line: str) -> dict | None:
    match = SSH_PATTERN.search(line)
    if not match:
        return None
    data = match.groupdict()
    current_year = datetime.now().year
    dt_str = f"{current_year} {data['month']} {data['day']} {data['time']}"
    dt = datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")
    
    return {
        "timestamp": dt,
        "source_ip": data["ip"],
        "event_type": "ssh_auth",
        "user": data["user"],
        "status": "failed" if data["status"] == "Failed" else "success",
        "path": None
    }

def load_logs(file_path: str) -> tuple[pd.DataFrame, int]:
    records = []
    failed_lines = 0

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            parsed = parse_ssh_line(line.strip())
            if parsed:
                records.append(parsed)
            else:
                failed_lines += 1

    df = pd.DataFrame(records)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df, failed_lines


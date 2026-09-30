import re
from datetime import datetime
import pandas as pd

SSH_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+'
    r'(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid\u0020user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)'
)

WEB_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[0-9.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
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

def load_logs(file_path: str, log_type: str) -> tuple[pd.DataFrame, int]:
    records = []
    failed_lines = 0
    parser = parse_ssh_line 

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            parsed = parser(line.strip())
            if parsed:
                records.append(parsed)
            else:
                failed_lines += 1

    df = pd.DataFrame(records)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df, failed_lines


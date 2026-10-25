import pandas as pd

from src.detector import ThreatDetector
from src.parser import parse_ssh_line

CONFIG = {"ssh_brute_force": {"failed_attempts": 5, "window_minutes": 10}}


def _df(n, ip="10.0.0.1"):
    lines = [f"Jan 10 14:3{i}:01 srv sshd[1]: Failed password for root from {ip} port 22 ssh2" for i in range(n)]
    return pd.DataFrame([parse_ssh_line(l) for l in lines])


def test_flags_brute_force():
    assert ThreatDetector(CONFIG).detect_ssh_brute_force(_df(6))["source_ip"].tolist() == ["10.0.0.1"]


def test_ignores_low_volume():
    assert ThreatDetector(CONFIG).detect_ssh_brute_force(_df(3)).empty

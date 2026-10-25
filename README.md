# Log Analyzer

A small command-line tool that reads an SSH authentication log, detects brute-force attempts with a configurable rule, and writes a report with suggested firewall rules.

Written in Python with pandas. Includes unit tests and a GitHub Actions pipeline (lint + tests).

## What it does

1. Parses `sshd` "Failed password" / "Accepted password" lines into a table (timestamp, source IP, user, status).
2. Flags any IP with **N failed logins inside a sliding time window** (defaults: 5 failures in 10 minutes, set in `config/rules.yaml`).
3. Writes a Markdown report and prints suggested `nftables` or `iptables` block rules.

Firewall rules are **suggestions only**. Nothing is executed. Review them before use, because blocking an IP is not always the right call.

## Install

Requires Python 3.10 or newer.

```bash
git clone https://github.com/kabi-ctr/log_analyzer.git
cd log_analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m src.cli OpenSSH_2k.log
```

Run it with `python -m src.cli` from the repo root. `python src/cli.py` will not work.

| Option | Default | Description |
|---|---|---|
| `log_file` | (required) | Path to the SSH auth log |
| `--config` | `config/rules.yaml` | Detection thresholds |
| `--report` | `report.md` | Where to write the report |
| `--fw-syntax` | `nftables` | `nftables` or `iptables` |

## Sample output

Running against the included `OpenSSH_2k.log` (2,000 lines from one host, 24 distinct source IPs, about 4 hours of activity):

**Terminal**

```text
--- Suggested Firewall Rules ---
# WARNING: Suggested rules only. Inspect before executing.

nft add rule inet filter input ip saddr 103.99.0.122 drop
nft add rule inet filter input ip saddr 112.95.230.3 drop
nft add rule inet filter input ip saddr 119.4.203.64 drop
nft add rule inet filter input ip saddr 123.235.32.19 drop
nft add rule inet filter input ip saddr 183.62.140.253 drop
nft add rule inet filter input ip saddr 185.190.58.151 drop
nft add rule inet filter input ip saddr 187.141.143.180 drop
nft add rule inet filter input ip saddr 5.188.10.180 drop
nft add rule inet filter input ip saddr 60.2.12.12 drop
```

**`report.md`**

| source_ip       | reason          |   count |
|:----------------|:----------------|--------:|
| 103.99.0.122    | SSH Brute Force |      30 |
| 112.95.230.3    | SSH Brute Force |      26 |
| 119.4.203.64    | SSH Brute Force |       6 |
| 123.235.32.19   | SSH Brute Force |       7 |
| 183.62.140.253  | SSH Brute Force |     279 |
| 185.190.58.151  | SSH Brute Force |      17 |
| 187.141.143.180 | SSH Brute Force |      80 |
| 5.188.10.180    | SSH Brute Force |      18 |
| 60.2.12.12      | SSH Brute Force |       5 |

`count` is the number of failed attempts inside the first window that crossed the threshold, not the total for that IP.

## Configuration

`config/rules.yaml`:

```yaml
ssh_brute_force:
  failed_attempts: 5     # failures needed to flag an IP
  window_minutes: 10     # sliding window size
```

## Development

```bash
pip install -r requirements-dev.txt
ruff check src/ tests/
pytest
```

CI runs the same two commands on every push and pull request.

## Project layout

```text
src/
  cli.py        command-line entry point
  parser.py     log line -> structured record
  detector.py   rule-based brute-force detection
  reporter.py   Markdown report and firewall rule output
config/rules.yaml
tests/
OpenSSH_2k.log  sample data
```

## Known limitations

- Only SSH password logins are parsed. Key-based logins and "Invalid user" lines are not counted yet, so attack volume is understated.
- Syslog lines carry no year, so the parser assumes the current year.
- The "Unparsed Lines" figure in the report counts every line that is not a password login, including normal sshd messages. It does not mean the file is corrupt.
- Rule-based detection only. It will miss slow, distributed attacks that stay under the threshold.

## Roadmap

- [ ] Isolation Forest anomaly detector on per-IP login features, compared against the rule-based detector
- [ ] Count "Invalid user" attempts
- [ ] Ingest logs into Microsoft Sentinel

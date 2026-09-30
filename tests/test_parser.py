from src.parser import parse_ssh_line

def test_parse_ssh_failed():
    line = "Jan 10 14:32:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 4522 ssh2"
    parsed = parse_ssh_line(line)
    assert parsed is not None
    assert parsed["source_ip"] == "192.168.1.100"
    assert parsed["status"] == "failed"
    assert parsed["user"] == "root"

import pytest
from agent.parser import parse_vulnerability_input


def test_empty_input():
    success, msg, data = parse_vulnerability_input("")
    assert not success
    assert "empty" in msg.lower()
    assert data == {}


def test_malformed_json():
    raw = '{"vulnerabilities": [{"name": "SQLi", "severity": "HIGH"'  # Missing closing braces
    success, msg, data = parse_vulnerability_input(raw)
    assert not success
    assert "malformed json" in msg.lower()


def test_valid_json():
    raw = '''
    {
      "target": "192.168.1.100",
      "scanner": "CustomAudit",
      "vulnerabilities": [
        {
          "title": "Remote Code Execution",
          "severity": "CRITICAL",
          "cve": "CVE-2024-1234",
          "component": "Apache/2.4.49",
          "description": "Path traversal flaw allows arbitrary code execution."
        }
      ]
    }
    '''
    success, msg, data = parse_vulnerability_input(raw)
    assert success
    assert data["metadata"]["target"] == "192.168.1.100"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["cve"] == "CVE-2024-1234"
    assert "recon" in data


def test_malformed_xml():
    raw = "<nmaprun><host><address addr='10.0.0.1'></host>"  # Mismatched tags
    success, msg, data = parse_vulnerability_input(raw)
    assert not success
    assert "malformed xml" in msg.lower()


def test_valid_nmap_xml():
    raw = '''<?xml version="1.0"?>
    <nmaprun args="nmap -sV -p 22,80 10.0.0.5">
      <host>
        <address addr="10.0.0.5" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.2p1"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    '''
    success, msg, data = parse_vulnerability_input(raw)
    assert success
    assert data["metadata"]["target"] == "10.0.0.5"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["affected_component"] == "10.0.0.5:22"
    assert "recon" in data


def test_deep_recon_nmap_xml():
    with open("data/sample_deep_recon.xml", "r", encoding="utf-8") as f:
        raw = f.read()
    success, msg, data = parse_vulnerability_input(raw)
    assert success
    assert "recon" in data
    recon = data["recon"]
    assert recon["total_hosts"] == 3
    assert len(recon["hosts"]) == 3
    
    # Verify OS detection in recon
    host0 = recon["hosts"][0]
    assert host0["ip"] == "192.168.10.45"
    assert "Windows Server" in host0["os"]
    assert host0["mac"] == "00:0C:29:4F:8E:1A"
    assert host0["vendor"] == "VMware"
    assert "app-server.corp.local" in host0["hostnames"]


def test_authenticated_scan_json():
    with open("data/sample_authenticated_scan.json", "r", encoding="utf-8") as f:
        raw = f.read()
    success, msg, data = parse_vulnerability_input(raw)
    assert success
    assert data["metadata"]["authenticated_audit"] is True
    assert "Domain Admin" in data["metadata"]["credentials_profile"]
    assert len(data["findings"]) == 4
    assert any(f["title"].startswith("Linux Kernel") for f in data["findings"])
    assert any(f["authenticated_check"] for f in data["findings"])


def test_nessus_xml_parsing():
    with open("data/sample_nessus.xml", "r", encoding="utf-8") as f:
        raw = f.read()
    success, msg, data = parse_vulnerability_input(raw)
    assert success
    assert "nessus" in data["metadata"]["scanner"].lower()
    assert data["metadata"]["authenticated_audit"] is True
    assert len(data["findings"]) == 5
    assert len(data["recon"]["hosts"]) == 2
    
    # Check EternalBlue critical finding
    eternal = next(f for f in data["findings"] if "EternalBlue" in f["title"])
    assert eternal["severity"] == "CRITICAL"
    assert eternal["cve"] == "CVE-2017-0144"
    assert eternal["cvss"] == "9.8"
    assert "192.168.1.15:445" in eternal["affected_component"]
    assert eternal["authenticated_check"] is True

    # Check hosts recon
    hosts = data["recon"]["hosts"]
    assert hosts[0]["ip"] == "192.168.1.15"
    assert "Windows Server" in hosts[0]["os"]
    assert "dc01.corp.internal" in hosts[0]["hostnames"]
    assert hosts[1]["ip"] == "192.168.1.42"
    assert "Ubuntu Linux" in hosts[1]["os"]


def test_nuclei_json_parsing():
    with open("data/sample_nuclei.json", "r", encoding="utf-8") as f:
        raw = f.read()
    success, msg, data = parse_vulnerability_input(raw)
    assert success
    assert "nuclei" in data["metadata"]["scanner"].lower()
    assert len(data["findings"]) == 4
    
    # Check Log4Shell finding
    log4j = next(f for f in data["findings"] if "Log4j" in f["title"])
    assert log4j["severity"] == "CRITICAL"
    assert log4j["cve"] == "CVE-2021-44228"
    assert log4j["cvss"] == "10.0"
    assert "8443" in log4j["affected_component"]
    
    # Check severity breakdown
    breakdown = data["recon"]["severity_breakdown"]
    assert breakdown["CRITICAL"] == 2
    assert breakdown["HIGH"] == 2
    assert len(data["recon"]["hosts"]) >= 3


def test_nuclei_jsonl_parsing():
    # Test line-delimited JSON stream (JSONL)
    jsonl_raw = (
        '{"template-id": "cve-2021-44228", "info": {"name": "Log4Shell", "severity": "critical", "classification": {"cve-id": "CVE-2021-44228", "cvss-score": 10.0}}, "host": "http://target1:8080", "ip": "10.0.0.1"}\n'
        '{"template-id": "exposed-git", "info": {"name": "Exposed Git Repository", "severity": "medium"}, "host": "http://target2:80", "ip": "10.0.0.2"}\n'
    )
    success, msg, data = parse_vulnerability_input(jsonl_raw)
    assert success
    assert "nuclei" in data["metadata"]["scanner"].lower()
    assert len(data["findings"]) == 2
    assert data["findings"][0]["cve"] == "CVE-2021-44228"
    assert data["findings"][1]["severity"] == "MEDIUM"


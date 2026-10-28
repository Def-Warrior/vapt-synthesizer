from agent.report_generator import generate_executive_html_dossier


def test_generate_executive_html_dossier_basic():
    scan_data = {
        "metadata": {"target": "192.168.1.0/24", "scan_type": "Nmap Recon", "authenticated_audit": False},
        "recon": {
            "total_hosts": 1,
            "total_open_ports": 2,
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "hostnames": ["gateway.local"],
                    "os": "Linux 5.4",
                    "mac": "00:11:22:33:44:55",
                    "vendor": "VMware",
                    "traceroute_hops": 1,
                    "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "8.2p1"}]
                }
            ]
        },
        "findings": [
            {
                "title": "OpenSSH Weak Cipher",
                "severity": "CRITICAL",
                "cve": "CVE-2021-0001",
                "cvss": 9.8,
                "affected_component": "192.168.1.10:22",
                "description": "Critical buffer overflow in sshd.",
                "remediation": "Upgrade OpenSSH to >= 8.9"
            }
        ]
    }
    user_profile = {
        "name": "Faizan Hassan",
        "role": "Lead Security Researcher",
        "clearance": "Top Secret // Operational",
        "session_token": "TOKEN-XYZ-12345"
    }

    report = generate_executive_html_dossier(scan_data, user_profile, ai_summary="Executive briefing text here")
    assert "<!DOCTYPE html>" in report
    assert "192.168.1.0/24" in report
    assert "Faizan Hassan" in report
    assert "CRITICAL EXPOSURE" in report
    assert "CVE-2021-0001" in report
    assert "Executive briefing text here" in report
    assert "NIST SP 800-115" in report


def test_generate_executive_html_dossier_empty_findings():
    scan_data = {"metadata": {"target": "10.0.0.1"}, "recon": {}, "findings": []}
    user_profile = {"name": "Analyst", "role": "Tester", "clearance": "Standard"}
    report = generate_executive_html_dossier(scan_data, user_profile)
    assert "HARDENED POSTURE" in report
    assert "No host cartography available" in report

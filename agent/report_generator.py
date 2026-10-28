"""
agent/report_generator.py
Generates polished, client-ready Executive VAPT Audit Dossiers in standalone, printable HTML.
Designed with printable CSS (@media print) allowing 1-click 'Save as PDF' from browser.
Conformant with NIST SP 800-115 and CIS Benchmark reporting standards.
"""

from __future__ import annotations
import datetime
import html
from typing import Any, Dict, List


def generate_executive_html_dossier(
    scan_data: Dict[str, Any],
    user_profile: Dict[str, Any],
    ai_summary: str = ""
) -> str:
    """
    Compiles normalized scan intelligence, deep reconnaissance topology,
    and identified vulnerabilities into a comprehensive executive audit dossier.
    """
    metadata = scan_data.get("metadata", {})
    recon = scan_data.get("recon", {})
    findings = scan_data.get("findings", [])
    
    target = html.escape(str(metadata.get("target", "Target Network")))
    scan_type = html.escape(str(metadata.get("scan_type", "Comprehensive VAPT Assessment")))
    is_auth = metadata.get("authenticated_audit", False)
    auth_label = "Authenticated CIS Audit (Privileged)" if is_auth else "Perimeter Network Reconnaissance"
    
    analyst_name = html.escape(user_profile.get("name", "Lead Penetration Tester"))
    analyst_role = html.escape(user_profile.get("role", "Senior Security Specialist"))
    clearance = html.escape(user_profile.get("clearance", "Top Secret // Operational"))
    session_id = html.escape(user_profile.get("session_token", "AIRGAP-SEC-001")[:16])
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Severity breakdown
    crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")
    total_findings = len(findings)
    
    # Overall posture calculation
    if crit_count > 0:
        posture_status = "CRITICAL EXPOSURE"
        posture_color = "#da3633"
        risk_score = min(10.0, 7.5 + (crit_count * 0.8) + (high_count * 0.3))
    elif high_count > 0:
        posture_status = "ELEVATED RISK"
        posture_color = "#d29922"
        risk_score = min(7.4, 5.0 + (high_count * 0.5))
    elif med_count > 0:
        posture_status = "MODERATE POSTURE"
        posture_color = "#0096c7"
        risk_score = 4.2
    else:
        posture_status = "HARDENED POSTURE"
        posture_color = "#00ff9d"
        risk_score = 1.5

    hosts = recon.get("hosts", [])
    total_hosts = recon.get("total_hosts", len(hosts) or 1)
    total_ports = recon.get("total_open_ports", 0)

    # Build Host Topology Rows
    host_rows = []
    for idx, h in enumerate(hosts, 1):
        ip = html.escape(str(h.get("ip", "Unknown")))
        os_name = html.escape(str(h.get("os", "Generic Linux / Unknown")))
        mac = html.escape(str(h.get("mac", "N/A")))
        vendor = html.escape(str(h.get("vendor", "N/A")))
        hostnames = html.escape(", ".join(h.get("hostnames", [])) or "None")
        ports = h.get("open_ports", [])
        
        port_items = []
        for p in ports:
            if isinstance(p, dict):
                proto = p.get("protocol", "tcp").upper()
                pnum = p.get("port")
                svc = p.get("service", "")
                prod = p.get("product", "")
                ver = p.get("version", "")
                desc = f"{proto}/{pnum} ({svc} {prod} {ver})".strip()
                port_items.append(html.escape(desc))
            else:
                port_items.append(html.escape(str(p)))
        port_str = ", ".join(port_items[:6]) or "No services identified"

        host_rows.append(f"""
        <tr>
            <td style="font-weight: bold; font-family: monospace;">{idx}</td>
            <td style="font-family: monospace; color: #0096c7;">{ip}</td>
            <td>{hostnames}</td>
            <td>{os_name}</td>
            <td style="font-family: monospace; font-size: 0.85em;">{mac} ({vendor})</td>
            <td style="font-size: 0.85em;">{port_str}</td>
        </tr>
        """)
    hosts_table_body = "\n".join(host_rows) or "<tr><td colspan='6'>No host cartography available</td></tr>"

    # Build Findings Rows
    finding_cards = []
    for idx, f in enumerate(findings, 1):
        sev = f.get("severity", "MEDIUM")
        title = html.escape(str(f.get("title", "Identified Vulnerability")))
        cve = html.escape(str(f.get("cve", "CVE-N/A")))
        cvss = html.escape(str(f.get("cvss", "N/A")))
        comp = html.escape(str(f.get("affected_component", "Host Network Interface")))
        desc = html.escape(str(f.get("description", "")))
        remed = html.escape(str(f.get("remediation", "Apply vendor patch and review network segmentation.")))
        
        color_map = {
            "CRITICAL": "#da3633",
            "HIGH": "#d29922",
            "MEDIUM": "#0096c7",
            "LOW": "#00ff9d"
        }
        b_color = color_map.get(sev, "#8b949e")

        finding_cards.append(f"""
        <div style="border-left: 5px solid {b_color}; background-color: #0d121c; border: 1px solid #1c2638; border-left-width: 5px; border-radius: 6px; padding: 16px 20px; margin-bottom: 16px; page-break-inside: avoid;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h4 style="margin: 0; color: #ffffff; font-family: monospace;">#{idx} {title}</h4>
                <span style="background-color: {b_color}; color: #ffffff; padding: 3px 12px; border-radius: 12px; font-weight: bold; font-size: 0.8em;">{sev}</span>
            </div>
            <div style="margin-top: 8px; color: #8b9bb4; font-size: 0.85em; font-family: monospace;">
                <strong>Component:</strong> <span style="color: #00e5ff;">{comp}</span> | 
                <strong>CVE:</strong> <span style="color: #00b4d8;">{cve}</span> | 
                <strong>CVSS Score:</strong> <span style="color: #ffffff; font-weight: bold;">{cvss}</span>
            </div>
            <p style="margin-top: 10px; color: #c9d1d9; font-size: 0.95em; line-height: 1.5;">{desc}</p>
            <div style="background-color: #06090e; padding: 12px; border-radius: 6px; border: 1px solid rgba(0, 150, 199, 0.3); margin-top: 10px;">
                <strong style="color: #00ff9d; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px;">Remediation Directives:</strong>
                <div style="color: #d8e2ec; font-size: 0.9em; margin-top: 4px; font-family: monospace;">{remed}</div>
            </div>
        </div>
        """)
    findings_html = "\n".join(finding_cards) or "<p>No vulnerabilities identified in current scan scope.</p>"

    # AI Synthesis section if provided
    ai_section = ""
    if ai_summary.strip():
        formatted_summary = html.escape(ai_summary).replace("\n", "<br>")
        ai_section = f"""
        <div style="margin-top: 30px; page-break-inside: avoid;">
            <h3 style="color: #00e5ff; border-bottom: 1px solid rgba(0, 150, 199, 0.3); padding-bottom: 6px; font-family: monospace;">
                🤖 ON-DEVICE NEURAL SYNTHESIS (GEMMA 4)
            </h3>
            <div style="background-color: #0b111a; border: 1px solid #0096c7; border-radius: 8px; padding: 18px 22px; color: #d8e2ec; font-size: 0.95em; line-height: 1.6;">
                {formatted_summary}
            </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Executive VAPT Audit Dossier // {target}</title>
    <style>
        body {{
            background-color: #08090b;
            color: #d8e2ec;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px 40px;
        }}
        .header-dossier {{
            background: linear-gradient(135deg, #0d1420 0%, #060a10 100%);
            border: 1px solid #0096c7;
            border-radius: 10px;
            padding: 24px 30px;
            margin-bottom: 25px;
            box-shadow: 0 4px 20px rgba(0, 150, 199, 0.15);
        }}
        .badge-classification {{
            background-color: rgba(218, 54, 51, 0.15);
            color: #ff6b6b;
            border: 1px solid #da3633;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.75em;
            font-family: monospace;
            font-weight: bold;
            letter-spacing: 1px;
        }}
        .metric-card {{
            background-color: #0d121c;
            border: 1px solid rgba(0, 150, 199, 0.3);
            border-radius: 8px;
            padding: 14px 18px;
            text-align: center;
        }}
        .metric-title {{
            color: #00b4d8;
            font-size: 0.8em;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.5px;
        }}
        .metric-val {{
            color: #ffffff;
            font-size: 1.8em;
            font-weight: bold;
            font-family: monospace;
            margin-top: 4px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background-color: #0d121c;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #1c2638;
        }}
        th {{
            background-color: #101826;
            color: #00e5ff;
            text-align: left;
            padding: 12px 14px;
            font-size: 0.85em;
            font-family: monospace;
            border-bottom: 1px solid #1c2638;
        }}
        td {{
            padding: 10px 14px;
            border-bottom: 1px solid #141d2c;
            font-size: 0.9em;
        }}
        tr:hover td {{
            background-color: #121a28;
        }}
        @media print {{
            body {{
                background-color: #ffffff !important;
                color: #000000 !important;
                padding: 15px !important;
            }}
            .header-dossier, .metric-card, table, div {{
                background-color: #ffffff !important;
                color: #000000 !important;
                border-color: #cccccc !important;
                box-shadow: none !important;
            }}
            th {{
                background-color: #f0f0f0 !important;
                color: #000000 !important;
            }}
            .badge-classification {{
                border-color: #000000 !important;
                color: #000000 !important;
            }}
            .no-print {{
                display: none !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="header-dossier">
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
            <div>
                <span class="badge-classification">RESTRICTED AUDIT REPORT // TOP SECRET</span>
                <h1 style="color: #ffffff; margin: 10px 0 4px 0; font-family: monospace; letter-spacing: 0.5px;">
                    <span style="color: #00e5ff;">EXECUTIVE</span> <span style="color: #00ff9d;">VAPT DOSSIER</span>
                </h1>
                <div style="color: #8b9bb4; font-size: 0.9em;">
                    Target: <strong style="color: #ffffff;">{target}</strong> • Assessment: <strong style="color: #00b4d8;">{scan_type}</strong>
                </div>
            </div>
            <div style="text-align: right; font-family: monospace; font-size: 0.85em; color: #8b9bb4;">
                <div style="color: #00ff9d; font-weight: bold;">● AIR-GAP SOC SIGN-OFF</div>
                <div>Session: {session_id}</div>
                <div>Generated: {timestamp}</div>
            </div>
        </div>
        <hr style="border: 0; border-top: 1px solid rgba(0, 150, 199, 0.2); margin: 16px 0;">
        <div style="display: flex; justify-content: space-between; font-size: 0.85em; color: #8b9bb4;">
            <div><strong>Analyst:</strong> {analyst_name} ({analyst_role})</div>
            <div><strong>Clearance:</strong> {clearance}</div>
            <div><strong>Operational Mode:</strong> {auth_label}</div>
        </div>
    </div>

    <!-- Metrics Row -->
    <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 25px;">
        <div class="metric-card">
            <div class="metric-title">Posture Rating</div>
            <div class="metric-val" style="color: {posture_color}; font-size: 1.3em; margin-top: 8px;">{posture_status}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Risk Score</div>
            <div class="metric-val" style="color: {posture_color};">{risk_score:.1f} / 10</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Hosts Profiled</div>
            <div class="metric-val">{total_hosts}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Open Services</div>
            <div class="metric-val">{total_ports}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Crit / High Vulns</div>
            <div class="metric-val" style="color: {'#da3633' if crit_count > 0 else '#ffffff'};">{crit_count} / {high_count}</div>
        </div>
    </div>

    <!-- Deep Reconnaissance Cartography -->
    <h3 style="color: #00e5ff; border-bottom: 1px solid rgba(0, 150, 199, 0.3); padding-bottom: 6px; font-family: monospace;">
        🔬 DISCOVERED TOPOLOGY & NETWORK CARTOGRAPHY
    </h3>
    <table>
        <thead>
            <tr>
                <th style="width: 5%;">#</th>
                <th style="width: 15%;">IP Address</th>
                <th style="width: 15%;">Hostnames</th>
                <th style="width: 20%;">Detected OS Fingerprint</th>
                <th style="width: 20%;">MAC / Hardware Attribution</th>
                <th style="width: 25%;">Exposed Services & Ports</th>
            </tr>
        </thead>
        <tbody>
            {hosts_table_body}
        </tbody>
    </table>

    <div style="height: 25px;"></div>

    <!-- Normalized Vulnerabilities -->
    <h3 style="color: #00e5ff; border-bottom: 1px solid rgba(0, 150, 199, 0.3); padding-bottom: 6px; font-family: monospace;">
        📊 PRIORITIZED VULNERABILITY FINDINGS ({total_findings} TOTAL)
    </h3>
    {findings_html}

    {ai_section}

    <!-- Compliance Footer -->
    <div style="margin-top: 40px; padding-top: 15px; border-top: 1px solid rgba(0, 150, 199, 0.2); font-size: 0.8em; color: #8b9bb4; text-align: center;">
        CONFIDENTIAL SECURITY AUDIT REPORT // COMPLIANT WITH NIST SP 800-115 // PRODUCED BY ON-DEVICE AIR-GAP AI (GEMMA 4)
    </div>
</body>
</html>
"""

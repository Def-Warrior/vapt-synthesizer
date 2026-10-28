"""
agent/parser.py
Parses Nmap XML, Tenable Nessus XML, ProjectDiscovery Nuclei JSON/JSONL,
and generic vulnerability JSON formats into normalized schemas.
Safe against malformed, partial, or empty input.
Extracts deep reconnaissance topology, host profiling, and authenticated audit evidence.
"""

from __future__ import annotations
import json
import re
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Tuple


def parse_vulnerability_input(raw_content: str) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Auto-detects format (JSON, JSONL, Nmap XML, Nessus XML) and returns normalized scan context with deep recon.
    Returns: (success: bool, message: str, normalized_data: dict)
    """
    cleaned = raw_content.strip()
    if not cleaned:
        return False, "Input file is empty.", {}

    # Attempt JSON / JSONL parsing first
    if cleaned.startswith("{") or cleaned.startswith("["):
        try:
            parsed_json = json.loads(cleaned)
            return _normalize_json(parsed_json)
        except json.JSONDecodeError:
            # Check for line-delimited JSON (JSONL - common for Nuclei)
            lines = [l.strip() for l in cleaned.splitlines() if l.strip()]
            if lines:
                try:
                    parsed_list = [json.loads(l) for l in lines]
                    return _normalize_json(parsed_list)
                except Exception as err:
                    return False, f"Malformed JSON: {str(err)}", {}
            return False, "Malformed JSON format.", {}

    # Attempt XML parsing (Nmap XML or Nessus XML)
    if cleaned.startswith("<"):
        try:
            root = ET.fromstring(cleaned)
            root_tag_lower = root.tag.lower()
            if "nmaprun" in root_tag_lower:
                return _normalize_nmap_xml(root)
            elif "nessus" in root_tag_lower or root.find(".//ReportHost") is not None or root.find(".//Report") is not None:
                return _normalize_nessus_xml(root)
            return False, f"Unsupported XML root tag: <{root.tag}>. Expected <nmaprun> or <NessusClientData_v2>.", {}
        except ET.ParseError as err:
            return False, f"Malformed XML: {str(err)}", {}

    return False, "Unrecognized format. Upload valid JSON, JSONL, Nmap XML, or Nessus XML.", {}


def _normalize_json(data: Any) -> Tuple[bool, str, Dict[str, Any]]:
    # Check if this is ProjectDiscovery Nuclei JSON output
    if isinstance(data, list) and len(data) > 0 and any("template-id" in str(item) or "templateID" in str(item) for item in data[:3]):
        return _normalize_nuclei_findings(data)
    if isinstance(data, dict) and ("template-id" in data or "templateID" in data):
        return _normalize_nuclei_findings([data])

    if isinstance(data, list):
        findings = data
        scan_meta = {
            "target": "Multiple / Array",
            "scanner": "Generic JSON List",
            "scan_type": "Vulnerability Scan",
            "authenticated_audit": False
        }
        raw_hosts = []
    elif isinstance(data, dict):
        findings = data.get("vulnerabilities") or data.get("findings") or data.get("issues") or []
        is_authenticated = bool(
            data.get("authenticated") or
            data.get("authenticated_audit") or
            data.get("credentials_used") or
            "authenticated" in str(data.get("audit_type", "")).lower() or
            "authenticated" in str(data.get("scanner", "")).lower()
        )
        scan_meta = {
            "target": data.get("target") or data.get("host") or "Unknown Target",
            "scanner": data.get("scanner") or data.get("tool") or "Generic JSON Scanner",
            "scan_date": data.get("date") or data.get("timestamp") or "N/A",
            "scan_type": data.get("audit_type") or ("Authenticated Audit" if is_authenticated else "Vulnerability Scan"),
            "authenticated_audit": is_authenticated,
            "credentials_profile": data.get("credentials_profile") or data.get("credentials_used") or ("Provided" if is_authenticated else "None (Unauthenticated)")
        }
        raw_hosts = data.get("hosts") or data.get("recon_hosts") or []
    else:
        return False, "JSON content must be an object or list of findings.", {}

    normalized_findings: List[Dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        
        # Check if finding is an authenticated/compliance finding
        is_auth_finding = bool(
            item.get("authenticated_check") or
            item.get("cis_benchmark") or
            item.get("patch_status") or
            "credential" in item.get("title", "").lower() or
            "authenticated" in item.get("description", "").lower()
        )
        if is_auth_finding and not scan_meta.get("authenticated_audit"):
            scan_meta["authenticated_audit"] = True
            scan_meta["scan_type"] = "Authenticated Deep Audit"

        normalized_findings.append({
            "title": item.get("title") or item.get("name") or "Unspecified Vulnerability",
            "severity": (item.get("severity") or "MEDIUM").upper(),
            "cve": item.get("cve") or item.get("cve_id") or "N/A",
            "cvss": item.get("cvss") or item.get("cvss_score") or "N/A",
            "affected_component": item.get("component") or item.get("host") or item.get("url") or "System",
            "description": item.get("description") or item.get("details") or "No description provided.",
            "remediation": item.get("remediation") or item.get("solution") or "Consult vendor guidance and apply recommended security patches.",
            "authenticated_check": is_auth_finding
        })

    # Build deep recon structure if present in JSON or synthesize from findings
    hosts_list: List[Dict[str, Any]] = []
    if raw_hosts and isinstance(raw_hosts, list):
        for h in raw_hosts:
            if isinstance(h, dict):
                hosts_list.append({
                    "ip": h.get("ip") or h.get("host") or "Unknown IP",
                    "hostnames": h.get("hostnames") or ([h["hostname"]] if "hostname" in h else []),
                    "os": h.get("os") or "Unknown OS",
                    "open_ports": h.get("open_ports") or h.get("ports") or [],
                    "status": h.get("status") or "up"
                })
    else:
        # Extract unique components from findings to build initial host recon profile
        unique_components = {f["affected_component"] for f in normalized_findings}
        hosts_list = [{
            "ip": scan_meta["target"],
            "hostnames": [],
            "os": "Inferred from scan metadata",
            "open_ports": list(unique_components),
            "status": "up"
        }]

    recon_summary = {
        "hosts": hosts_list,
        "total_hosts": len(hosts_list),
        "total_findings": len(normalized_findings),
        "severity_breakdown": {
            "CRITICAL": sum(1 for f in normalized_findings if f["severity"] == "CRITICAL"),
            "HIGH": sum(1 for f in normalized_findings if f["severity"] == "HIGH"),
            "MEDIUM": sum(1 for f in normalized_findings if f["severity"] == "MEDIUM"),
            "LOW": sum(1 for f in normalized_findings if f["severity"] == "LOW"),
        },
        "deep_recon": {
            "authenticated": scan_meta.get("authenticated_audit", False),
            "profile": scan_meta.get("credentials_profile", "None")
        }
    }

    return True, f"Successfully parsed {len(normalized_findings)} findings.", {
        "metadata": scan_meta,
        "recon": recon_summary,
        "findings": normalized_findings
    }


def _normalize_nuclei_findings(raw_items: List[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
    """Normalizes ProjectDiscovery Nuclei JSON or JSONL stream output."""
    findings: List[Dict[str, Any]] = []
    hosts_dict: Dict[str, Dict[str, Any]] = {}
    primary_target = "Unknown Target"

    for item in raw_items:
        if not isinstance(item, dict):
            continue

        info = item.get("info") or {}
        template_id = item.get("template-id") or item.get("templateID", "nuclei-finding")
        title = info.get("name") or template_id

        raw_sev = str(info.get("severity", "medium")).upper()
        if raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity = raw_sev
        else:
            severity = "LOW"  # Map INFO / UNKNOWN to LOW

        classif = info.get("classification") or {}
        cve_val = classif.get("cve-id")
        if isinstance(cve_val, list):
            cve = ", ".join(cve_val)
        elif isinstance(cve_val, str):
            cve = cve_val
        else:
            m = re.search(r"cve-\d{4}-\d+", template_id, re.IGNORECASE)
            cve = m.group(0).upper() if m else "N/A"

        cvss = classif.get("cvss-score") or classif.get("cvss_score") or "N/A"

        host_val = item.get("host") or item.get("matched-at") or "Unknown Host"
        ip_val = item.get("ip") or host_val
        if primary_target == "Unknown Target":
            primary_target = host_val

        desc = info.get("description") or f"Detected vulnerability via Nuclei template: {template_id}"

        remediation = info.get("remediation")
        if not remediation:
            refs = info.get("reference")
            if refs and isinstance(refs, list):
                remediation = f"Review vendor security bulletin: {', '.join(str(r) for r in refs[:2])}"
            else:
                remediation = "Apply official security updates and disable unneeded services."

        affected_component = item.get("matched-at") or item.get("host") or ip_val

        findings.append({
            "title": title,
            "severity": severity,
            "cve": str(cve),
            "cvss": str(cvss),
            "affected_component": affected_component,
            "description": desc,
            "remediation": remediation,
            "authenticated_check": False
        })

        # Build host recon map
        port = "80"
        if "https://" in host_val.lower():
            port = "443"
        port_match = re.search(r":(\d+)", host_val)
        if port_match:
            port = port_match.group(1)

        host_key = ip_val
        if host_key not in hosts_dict:
            hosts_dict[host_key] = {
                "ip": ip_val,
                "hostnames": [host_val] if host_val != ip_val else [],
                "status": "up",
                "os": "Web Application / Inferred Linux Container",
                "mac": "N/A",
                "vendor": "N/A",
                "open_ports": [],
                "traceroute_hops": "N/A"
            }
        port_entry = {"port": port, "protocol": "tcp", "service": "http", "product": "web-service", "version": ""}
        if port_entry not in hosts_dict[host_key]["open_ports"]:
            hosts_dict[host_key]["open_ports"].append(port_entry)

    hosts_recon = list(hosts_dict.values())
    recon_summary = {
        "hosts": hosts_recon,
        "total_hosts": len(hosts_recon),
        "total_open_ports": sum(len(h["open_ports"]) for h in hosts_recon),
        "deep_recon": {
            "os_detected": [h["os"] for h in hosts_recon],
            "scan_arguments": "ProjectDiscovery Nuclei Scan Engine",
            "authenticated": False
        },
        "severity_breakdown": {
            "CRITICAL": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "LOW": sum(1 for f in findings if f["severity"] == "LOW"),
        }
    }

    return True, f"Successfully parsed {len(findings)} findings from Nuclei scan.", {
        "metadata": {
            "target": primary_target,
            "scanner": "ProjectDiscovery Nuclei JSON",
            "scan_args": "nuclei -t cves/ -json",
            "scan_type": "Nuclei Automated Vulnerability Assessment",
            "authenticated_audit": False
        },
        "recon": recon_summary,
        "findings": findings
    }


def _normalize_nessus_xml(root: ET.Element) -> Tuple[bool, str, Dict[str, Any]]:
    """Parses Tenable Nessus XML format (.nessus / <NessusClientData_v2>)."""
    findings: List[Dict[str, Any]] = []
    hosts_recon: List[Dict[str, Any]] = []

    policy_el = root.find(".//policyName")
    scan_policy = policy_el.text.strip() if policy_el is not None and policy_el.text else "Nessus Vulnerability Scan"

    report_el = root.find(".//Report")
    report_name = report_el.attrib.get("name", "Nessus Audit") if report_el is not None else "Nessus Audit"

    is_authenticated_audit = False
    primary_target = "Unknown Target"

    for rhost in root.findall(".//ReportHost"):
        host_target = rhost.attrib.get("name", "Unknown Host")
        if primary_target == "Unknown Target":
            primary_target = host_target

        host_ip = host_target
        hostnames: List[str] = []
        detected_os = "Unknown OS"
        mac_addr = "N/A"
        vendor = "N/A"
        is_host_credentialed = False

        # Parse HostProperties
        props = rhost.find("HostProperties")
        if props is not None:
            for tag in props.findall("tag"):
                tname = tag.attrib.get("name", "")
                tval = (tag.text or "").strip()
                if tname in ("host-ip", "host_ip"):
                    host_ip = tval
                elif tname in ("host-fqdn", "netbios-name", "hostname"):
                    if tval and tval not in hostnames:
                        hostnames.append(tval)
                elif tname in ("operating-system", "os"):
                    detected_os = tval
                elif tname in ("mac-address", "mac"):
                    mac_addr = tval
                elif tname in ("credentialed_scan", "Credentialed_Scan") and tval.lower() == "true":
                    is_host_credentialed = True
                    is_authenticated_audit = True

        host_open_ports: List[Dict[str, Any]] = []
        seen_ports = set()

        for item in rhost.findall("ReportItem"):
            port = item.attrib.get("port", "0")
            svc_name = item.attrib.get("svc_name", "general")
            protocol = item.attrib.get("protocol", "tcp")
            severity_code = item.attrib.get("severity", "0")
            plugin_name = item.attrib.get("pluginName") or item.findtext("plugin_name") or "Unspecified Finding"

            # Severity mapping: 4: Critical, 3: High, 2: Medium, 1: Low, 0: Info
            risk_factor = (item.findtext("risk_factor") or "").upper()
            if severity_code == "4" or risk_factor == "CRITICAL":
                severity = "CRITICAL"
            elif severity_code == "3" or risk_factor == "HIGH":
                severity = "HIGH"
            elif severity_code == "2" or risk_factor == "MEDIUM":
                severity = "MEDIUM"
            elif severity_code == "1" or risk_factor == "LOW":
                severity = "LOW"
            else:
                severity = "LOW"

            cve = item.findtext("cve") or "N/A"
            cvss = item.findtext("cvss3_base_score") or item.findtext("cvss_base_score") or "N/A"
            desc = (item.findtext("description") or item.findtext("synopsis") or "No description provided.").strip()
            remediation = (item.findtext("solution") or "Apply vendor security updates and patch system.").strip()

            if port != "0" and port not in seen_ports:
                seen_ports.add(port)
                host_open_ports.append({
                    "port": port,
                    "protocol": protocol,
                    "service": svc_name,
                    "product": "",
                    "version": ""
                })

            affected = f"{host_ip}:{port}" if port != "0" else host_ip
            findings.append({
                "title": plugin_name,
                "severity": severity,
                "cve": cve,
                "cvss": cvss,
                "affected_component": affected,
                "description": desc,
                "remediation": remediation,
                "authenticated_check": is_host_credentialed
            })

        hosts_recon.append({
            "ip": host_ip,
            "hostnames": hostnames,
            "status": "up",
            "mac": mac_addr,
            "vendor": vendor,
            "os": detected_os,
            "traceroute_hops": "N/A",
            "open_ports": host_open_ports,
            "host_scripts": []
        })

    recon_summary = {
        "hosts": hosts_recon,
        "total_hosts": len(hosts_recon),
        "total_open_ports": sum(len(h["open_ports"]) for h in hosts_recon),
        "deep_recon": {
            "os_detected": [h["os"] for h in hosts_recon if h["os"] != "Unknown OS"],
            "scan_arguments": f"Policy: {scan_policy} | Report: {report_name}",
            "authenticated": is_authenticated_audit
        },
        "severity_breakdown": {
            "CRITICAL": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "LOW": sum(1 for f in findings if f["severity"] == "LOW"),
        }
    }

    return True, f"Successfully parsed {len(findings)} findings from Nessus scan.", {
        "metadata": {
            "target": primary_target,
            "scanner": "Tenable Nessus XML",
            "scan_args": scan_policy,
            "scan_type": "Nessus Enterprise Infrastructure Audit",
            "authenticated_audit": is_authenticated_audit
        },
        "recon": recon_summary,
        "findings": findings
    }


def _normalize_nmap_xml(root: ET.Element) -> Tuple[bool, str, Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    hosts_recon: List[Dict[str, Any]] = []
    primary_target = "Unknown"
    scan_args = root.attrib.get("args", "N/A")

    # Detect if authenticated scan arguments were passed
    is_authenticated = any(kw in scan_args.lower() for kw in [
        "smbuser", "smbpassword", "smbpass", "ssh-auth", "credentials", "auth="
    ])

    for host in root.findall("host"):
        # Host address and hardware info
        host_ip = "Unknown"
        mac_addr = "N/A"
        vendor = "N/A"
        for addr in host.findall("address"):
            addr_type = addr.attrib.get("addrtype", "")
            if addr_type in ("ipv4", "ipv6") and host_ip == "Unknown":
                host_ip = addr.attrib.get("addr", "Unknown")
            elif addr_type == "mac":
                mac_addr = addr.attrib.get("addr", "N/A")
                vendor = addr.attrib.get("vendor", "N/A")

        if primary_target == "Unknown" and host_ip != "Unknown":
            primary_target = host_ip

        # Host status
        status_el = host.find("status")
        host_status = status_el.attrib.get("state", "up") if status_el is not None else "up"

        # Hostnames
        hostnames: List[str] = []
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                name = hn.attrib.get("name")
                if name:
                    hostnames.append(name)

        # OS Detection (Deep Recon)
        detected_os = "Unknown OS"
        os_accuracy = 0
        os_el = host.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                detected_os = osmatch.attrib.get("name", "Unknown OS")
                os_accuracy = int(osmatch.attrib.get("accuracy", "0"))

        # Distance / Traceroute
        distance_el = host.find("distance")
        hops = distance_el.attrib.get("value", "N/A") if distance_el is not None else "N/A"

        # Hostscripts (SMB, NetBIOS, etc.)
        hostscript_findings: List[str] = []
        hostscript_el = host.find("hostscript")
        if hostscript_el is not None:
            for scr in hostscript_el.findall("script"):
                sid = scr.attrib.get("id", "host-script")
                sout = scr.attrib.get("output", "")
                hostscript_findings.append(f"[{sid}] {sout}")

        ports_el = host.find("ports")
        host_open_ports: List[Dict[str, Any]] = []

        if ports_el is not None:
            for port in ports_el.findall("port"):
                state = port.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue

                port_id = port.attrib.get("portid", "unknown")
                proto = port.attrib.get("protocol", "tcp")
                service = port.find("service")
                service_name = service.attrib.get("name", "unknown") if service is not None else "unknown"
                product = service.attrib.get("product", "") if service is not None else ""
                version = service.attrib.get("version", "") if service is not None else ""
                extrainfo = service.attrib.get("extrainfo", "") if service is not None else ""

                # Scripts output
                scripts = port.findall("script")
                script_findings = []
                is_vulnerable_script = False
                for script in scripts:
                    script_id = script.attrib.get("id", "script")
                    output = script.attrib.get("output", "")
                    script_findings.append(f"[{script_id}] {output}")
                    if any(v in output.lower() for v in ["vulnerable", "cve-", "exploit", "state: vulnerable"]):
                        is_vulnerable_script = True

                desc = f"Open service {service_name} ({product} {version} {extrainfo}).".strip()
                if script_findings:
                    desc += " Script findings: " + " | ".join(script_findings)

                severity = "HIGH" if (is_vulnerable_script or script_findings) else "LOW"
                if is_vulnerable_script:
                    severity = "CRITICAL" if any(k in desc.lower() for k in ["rce", "remote code", "overflow", "ms12-020"]) else "HIGH"

                findings.append({
                    "title": f"Exposed Service: {service_name} on {proto}/{port_id}",
                    "severity": severity,
                    "cve": "N/A",
                    "cvss": "N/A",
                    "affected_component": f"{host_ip}:{port_id}",
                    "description": desc.strip(),
                    "remediation": f"Restrict access to port {port_id} via network firewall and update {product or service_name} to latest hardened release."
                })

                host_open_ports.append({
                    "port": port_id,
                    "protocol": proto,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "scripts_count": len(scripts)
                })

        hosts_recon.append({
            "ip": host_ip,
            "hostnames": hostnames,
            "status": host_status,
            "mac": mac_addr,
            "vendor": vendor,
            "os": f"{detected_os} ({os_accuracy}% confidence)" if os_accuracy > 0 else detected_os,
            "traceroute_hops": hops,
            "open_ports": host_open_ports,
            "host_scripts": hostscript_findings
        })

    recon_summary = {
        "hosts": hosts_recon,
        "total_hosts": len(hosts_recon),
        "total_open_ports": sum(len(h["open_ports"]) for h in hosts_recon),
        "deep_recon": {
            "os_detected": [h["os"] for h in hosts_recon if h["os"] != "Unknown OS"],
            "scan_arguments": scan_args,
            "authenticated": is_authenticated
        },
        "severity_breakdown": {
            "CRITICAL": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "LOW": sum(1 for f in findings if f["severity"] == "LOW"),
        }
    }

    return True, f"Successfully extracted {len(findings)} open services/issues from Nmap scan.", {
        "metadata": {
            "target": primary_target,
            "scanner": "Nmap XML",
            "scan_args": scan_args,
            "scan_type": "Deep Reconnaissance Nmap Scan",
            "authenticated_audit": is_authenticated
        },
        "recon": recon_summary,
        "findings": findings
    }

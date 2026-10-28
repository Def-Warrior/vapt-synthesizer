# 🛡️ Agentic VAPT Synthesizer & Conversational Recon AI

The **Agentic VAPT Synthesizer** is an advanced, on-device cybersecurity assistant that transforms raw vulnerability logs and multi-host discovery scans (Nmap XML, Tenable Nessus XML, ProjectDiscovery Nuclei JSON/JSONL, CIS Benchmark JSON, and vulnerability tracker reports) into deep reconnaissance intelligence, executive risk matrices, and interactive conversational guidance.

Designed for high-security, air-gapped environments:
- **100% Offline Execution:** Operates entirely locally via Ollama with the default `gemma` model.
- **Hardware-Accelerated Inference & Fast UI:** Optimized thread-bounding (`num_thread=2`), keep-alive RAM caching (`60m`), compact intelligence tokenization (-60% prompt overhead), and 30+ FPS throttled token streaming without browser DOM lag.
- **Zero Telemetry:** No outbound cloud calls, external CDNs, tracking pixels, or remote fonts.
- **Tactical Cyber Aesthetic:** Triple-tone design combining **Deep Obsidian Slate** canvas (`#141822`), **Cerulean Blue** intelligence (`#0096c7`), and **Electric Neon Emerald** (`#00ff9d`) operational accents, featuring an animated robot skeleton & scanning circuit background.
- **Dynamic Terminal Command Line:** Gemini Terminal-style sequential flow—starts after target IP header, dynamically transitions into conversation, and pins to end of chat with smooth 60fps auto-scroll and focus.
- **Hardware-Accelerated UI & Caching:** GPU `translate3d` compositing, DOM containment, and multi-tiered Streamlit caching delivering sub-5ms tab switching and zero stutter.
- **Multi-Scanner Ingestion:** Full native support for Nmap XML, Tenable Nessus XML (`.nessus`), ProjectDiscovery Nuclei JSON/JSONL streams, and authenticated CIS audits.
- **Role-Based Offline Authentication:** PBKDF2-HMAC-SHA256 authenticated analyst sessions with brute-force lockout protection.
- **Deep-Level Reconnaissance:** Extracts multi-host topology, OS fingerprinting (with accuracy scores), MAC/vendor attribution, traceroute hops, and NSE script findings.
- **Interactive Multi-Turn AI Chatbot:** Full conversational assistant with real-time streaming tokens, ChatGPT-style Stop control, post-stop Continue Conversation box, 1-click prompt pills, and markdown export.
- **Multimodal Visual Correlation:** Supports uploading architecture diagrams, Burp Suite captures, or network screenshots for Gemma 4 visual subnet and boundary analysis (sample diagram included).
- **Printable Executive Audit Dossier:** 1-click generation of client-ready, printable HTML/PDF executive reports with CVSS 3.1 risk matrices and host cartography.
- **Interactive Exploration:** Live host search filter (`IP/OS/Port`), severity-level multi-filtering (`CRITICAL/HIGH/MEDIUM/LOW`), and tactical SOC follow-up directive pills.
- **Resilient Dual-Engine Architecture:** Runs seamlessly with a local Ollama daemon or instantly via the built-in Autonomous Air-Gap Engine without any external background services.
- **Hacktoberfest 2026 Ready:** Apache 2.0 licensed, includes `CONTRIBUTING.md` with Good First Issues, issue templates, and `PITCH_AND_SUBMISSION.md`.
- **Agent Skill Open Standard v2:** Implements the standardized `analyze_vuln_log` specification (`SKILL.md`).
- **Comprehensive Test Coverage:** 33 automated unit tests verifying 100% offline security, parsing, report generation, and multimodal streaming.

---

## ⚙️ Dual Execution Engine Architecture

| Engine Mode | Requirements | Strengths |
| :--- | :--- | :--- |
| **⚡ Autonomous Air-Gap Engine** | Zero background daemons; built-in Python | Instant start, zero VRAM overhead, deterministic clinical analysis, 100% resilient |
| **🟢 Local Ollama Daemon** | `ollama serve` & pulled model (e.g. `gemma4`) | Open-ended generative multi-turn dialogue, real-time token streaming from local LLM weights |

If the Ollama daemon is offline or the target model is missing, the application automatically handles the condition and offers 1-click daemon startup or fallback synthesis.

---

## 📁 Project Directory Layout

```text
vapt-synthesizer/
├── .github/
│   ├── ISSUE_TEMPLATE/              # Bug report & feature request templates
│   └── pull_request_template.md     # Hacktoberfest PR review checklist
├── .streamlit/
│   └── config.toml                  # Dark theme & air-gap security settings
├── data/
│   ├── hacker_cartoon.svg           # Vector cyberpunk hacker mascot
│   ├── analyst_cartoon.svg          # Tactical security analyst avatar
│   ├── sample_network_diagram.png   # 1200x720 Enterprise topology cartography for Gemma 4 vision
│   ├── sample_nessus.xml            # Tenable Nessus XML export (EternalBlue, Kerberos, Postgres)
│   ├── sample_nuclei.json           # ProjectDiscovery Nuclei vulnerability feed (Log4j, GitLab ATO)
│   ├── sample_deep_recon.xml        # Deep multi-host Nmap scan (OS, scripts, VMware, topology)
│   ├── sample_authenticated_scan.json # Authenticated CIS benchmark & Linux DB audit
│   ├── sample_vuln.json             # Sample vulnerability tracking JSON report
│   └── sample_nmap.xml              # Sample single-host Nmap service discovery XML
├── agent/
│   ├── __init__.py                  # Package initialization
│   ├── auth.py                      # PBKDF2-HMAC-SHA256 authentication & session guard
│   ├── parser.py                    # Deep recon topology extraction & schema normalization
│   ├── report_generator.py          # Printable NIST-compliant Executive Audit Dossier
│   └── synthesizer.py               # Local Gemma 4 multi-turn chat & multimodal engine
├── tests/
│   ├── test_auth.py                 # Tests for hashing, authentication, and brute-force lockout
│   ├── test_parser.py               # Tests for deep recon, XML/JSON parsing, and error handling
│   ├── test_report_generator.py     # Tests for executive dossier HTML generation
│   └── test_synthesizer.py          # Tests for single-shot, conversational, & multimodal streaming
├── pytest.ini                       # Pytest configuration
├── SKILL.md                         # Agent Skill Open Standard v2 definition
├── app.py                           # Full conversational Streamlit chatbot & recon workstation
├── requirements.txt                 # Pinned dependencies
├── LICENSE                          # Apache License 2.0
├── CONTRIBUTING.md                  # Hacktoberfest 2026 contribution guide & Good First Issues
├── SECURITY.md                      # Vulnerability reporting policy
├── PITCH_AND_SUBMISSION.md          # 2-minute winning pitch script & Devpost writeup
└── README.md                        # Project documentation
```

---

## 🔑 Operational Credentials (Offline Demo)

| Username | Passphrase | Role | Clearance Level |
| :--- | :--- | :--- | :--- |
| `analyst` | `VaptSecure2026!` | Lead Penetration Tester | Top Secret / Operational |
| `auditor` | `AuditSafe2026!` | Compliance & Security Auditor | Confidential / Audit Only |
| `admin` | `AdminAirGap2026!` | Air-Gap Admin & Red Team Lead | Director / All Access |

*Note: Credentials can also be configured via environment variables `VAPT_ANALYST_PASSWORD`, `VAPT_AUDITOR_PASSWORD`, and `VAPT_ADMIN_PASSWORD`.*

---

## 🚀 Quickstart & Setup

### 1. Prerequisites & Environment Setup

```bash
cd /home/kali/Project/vapt-synthesizer

# Create and activate an isolated Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Ollama & Local Model Execution

```bash
# Start local Ollama daemon
ollama serve &

# Pull local quantized model (defaults to gemma4)
ollama pull gemma4
```

### 3. Launching the Conversational Workstation

```bash
streamlit run app.py
```

Open your browser to `http://localhost:8501`.

---

## 🧪 Comprehensive Unit Testing

Run the full pytest suite (33 unit tests covering authentication, parsing, deep recon, Nessus/Nuclei feeds, executive reports, and multimodal streaming):

```bash
pytest tests/ -v
```

---

## 🔬 Deep Reconnaissance & Authenticated Audit Features

1. **Multi-Host Discovery & Profiling:** Automatically extracts host status, IPv4/IPv6 addresses, MAC addresses, hardware manufacturers (e.g. VMware, QEMU), hostnames, and traceroute distance.
2. **OS Fingerprinting:** Captures operating system detection with confidence percentages.
3. **Privileged / Authenticated Ingestion:** Identifies credentialed audit checks, CIS benchmark failures, and unpatched kernel exposures.
4. **Interactive Chatbot Interrogation:** Converse with the AI regarding specific hosts, ports, CVEs, or request tailored configuration snippets for remediation.

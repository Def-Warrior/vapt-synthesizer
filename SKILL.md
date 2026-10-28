---
name: analyze_vuln_log
version: 2.0.0
description: Ingests raw vulnerability scan logs (JSON or Nmap XML), extracts deep reconnaissance network topology and host profiles, performs authenticated session auditing, and powers an interactive multi-turn AI cybersecurity chatbot using local on-device LLMs.
author: Security Engineering Team
license: Apache-2.0
standard: Agent Skill Open Standard v2
privacy: Fully Local / Zero Telemetry / Air-Gapped Authenticated
---

# `analyze_vuln_log` (v2.0.0)

## Intent
Transform raw vulnerability and multi-host discovery logs into deep reconnaissance profiles, privileged audit assessments, and an interactive on-device AI conversational chatbot without dispatching sensitive telemetry off-host.

## Interface Definition

### Input Schema
- **`raw_data`** (`string`, required): Unprocessed string containing valid JSON or Nmap XML scan results.
- **`model_name`** (`string`, optional): Targeted local Ollama model (defaults to `gemma`, also supports `gemma4`, `llama3`).
- **`messages`** (`array`, optional): Conversation history for multi-turn assistant dialog.

### Output Schema
- **`recon`** (`object`): Deep reconnaissance summary including:
  1. Multi-host topology (IPs, MAC addresses, hardware vendors, FQDNs).
  2. Operating system detection and fingerprint confidence scores.
  3. Service discovery matrices and network script outputs.
- **`findings`** (`array`): Normalized vulnerability items with CVEs, CVSS ratings, and privileged audit status.
- **`chat_stream`** (`stream`): Real-time token streaming from local LLM for conversational Q&A.

## Execution Contract
1. Normalization preserves port numbers, software versions, CVEs, OS fingerprints, and contextual script execution.
2. Analyst authentication is enforced via PBKDF2-HMAC-SHA256 password verification before sensitive scan telemetry is presented.
3. The agent executes strictly against `localhost:11434` (local Ollama daemon). Outbound cloud network calls are strictly prohibited.

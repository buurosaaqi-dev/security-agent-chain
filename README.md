# Security Agent Chain (`agent-chain`)

> **Unified Autonomous Security & Bug Bounty Orchestration Pipeline for AI Agents and Security Researchers.**

`security-agent-chain` is a high-performance orchestration framework designed to connect reconnaissance, dynamic vulnerability scanning (DAST), static application security testing (SAST), and secrets detection into a single automated pipeline with structured JSON outputs.

Built specifically for:
- Autonomous AI coding and penetration testing agents (`Antigravity`, LLM CLI tools, local Ollama models).
- Bug bounty researchers conducting root-cause vulnerability analysis and attack surface mapping.
- CI/CD defensive verification.

---

## 🛠 Integrated Toolchain

| Category | Tool | Functionality |
| :--- | :--- | :--- |
| **Asset Discovery** | `subfinder` | Passive DNS enumeration & multi-source subdomain harvesting |
| **HTTP Probing** | `httpx` | Live web host probing, technology detection, and status codes |
| **Web Crawling** | `katana` | Headless & pipeline crawling for hidden endpoints and parameters |
| **Port Scanning** | `naabu` | Fast TCP port discovery and service mapping |
| **DAST & Triage** | `nuclei` | Automated template-based vulnerability assessment (CVEs, misconfigs) |
| **Fuzzing** | `ffuf` | High-speed directory, parameter, and vhost fuzzing |
| **Deduplication** | `anew` | Fast set operations and stream deduplication |
| **SAST** | `semgrep` | Semantic AST code pattern auditing |
| **Python SAST** | `bandit` | Python AST security flaw detection |
| **Secrets Audit** | `trufflehog`| Git and filesystem secret scanning with verification |
| **Proxy / Intercept**| `burpsuite` | Interactive proxy & traffic inspection |

---

## 🚀 Quick Start (CLI)

Ensure `agent-chain` is in your PATH (e.g. `~/.local/bin/agent-chain`):

```bash
# Check toolchain readiness
agent-chain status

# Run automated reconnaissance chain (Subfinder -> HTTPX -> Katana)
agent-chain recon example.com

# Run template-based vulnerability audit (Medium, High, Critical)
agent-chain audit https://example.com
# Or pass a list of discovered live hosts:
agent-chain audit results/example.com_YYYYMMDD_HHMMSS/live_hosts.txt

# Run SAST code & secrets scan on a source directory
agent-chain sast /path/to/project

# Launch Burp Suite in background
agent-chain burp
```

---

## 🤖 AI Agent & Programmatic Integration

Autonomous agents and LLMs can directly import `SecurityAgentChain` in Python to receive structured dictionary and JSON results:

```python
from pipeline.orchestrator import SecurityAgentChain

chain = SecurityAgentChain()

# 1. Check toolchain status
tools = chain.tools

# 2. Automated reconnaissance
recon_res = chain.run_recon("target.com")
print(f"Discovered {recon_res['live_hosts_count']} live hosts.")
print(f"Results stored in: {recon_res['target_dir']}")

# 3. Targeted vulnerability triage
audit_res = chain.run_nuclei_audit(f"{recon_res['target_dir']}/live_hosts.txt")
print(f"Identified {audit_res['findings_count']} potential findings.")

# 4. Source code security audit
sast_res = chain.run_sast_audit("/path/to/repo")
print(f"Semgrep findings: {sast_res['semgrep_findings_count']}")
```

---

## 📁 Result Structure

All operations store timestamped, deterministic artifacts in the `results/` directory:

```
results/
├── example.com_20261116_164500/
│   ├── subdomains.txt      # Raw harvested subdomains
│   ├── live_hosts.txt      # HTTPX validated live targets & tech stacks
│   ├── endpoints.txt       # Katana crawled endpoints
│   └── recon.json          # Machine-readable JSON summary for AI agents
├── nuclei_audit_20261116_165000.json
└── sast_20261116_165500/
    ├── semgrep.json
    └── trufflehog.json
```

---

## 🔒 Security & Defensive Framing

All workflows are strictly designed for authorized vulnerability research, defensive engineering, and bug bounty verification under responsible disclosure terms.

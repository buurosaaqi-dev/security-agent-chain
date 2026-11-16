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
| **JetBrains HTTP** | `ijhttp` | IntelliJ HTTP Client CLI for automated API fuzzing & requests |
| **JetBrains SAST** | `qodana` | JetBrains official static code security & vulnerability inspection |

---

## 🚀 Quick Start (CLI)

Ensure `agent-chain` is in your PATH (e.g. `~/.local/bin/agent-chain`):

```bash
# Check toolchain readiness
agent-chain status

# Create a locked scope policy, then review config/scope.json against
# the current HackerOne policy before enabling any network feature
agent-chain scope init PROGRAM_NAME target.example
agent-chain scope status
agent-chain scope check active_recon https://target.example

# Run automated reconnaissance chain (Subfinder -> HTTPX -> Katana)
agent-chain recon example.com

# Run template-based vulnerability audit (Medium, High, Critical)
agent-chain audit https://example.com
# Or pass a list of discovered live hosts:
agent-chain audit results/example.com_YYYYMMDD_HHMMSS/live_hosts.txt

# Run Semgrep + Bandit + redacted TruffleHog on an allowed local directory
agent-chain sast /path/to/project

# Run JetBrains HTTP Client payload or requests
agent-chain http "GET https://example.com/api"
# Or run an existing .http file:
agent-chain http exploits/test.http

# Run JetBrains Qodana static code security audit
agent-chain qodana /path/to/project

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

### MCP clients

The MCP server uses stdio, adds server-wide authorization instructions, and exposes
`scope_status` / `scope_check` alongside the scanner tools. Ready-to-merge examples are in:

- `integrations/opencode.jsonc`
- `integrations/codex-config.toml`
- `integrations/claude-desktop.json`

Every network method enforces the same scope file, exclusions, feature gates, required
headers, and request-rate limits. A missing or unconfirmed scope file fails closed.

---

## 📁 Result Structure

All operations store timestamped, deterministic artifacts in the `results/` directory:

```
results/
├── example.com_20261116_164500/
│   ├── subdomains.txt      # Raw harvested subdomains
│   ├── live_urls.txt       # Scoped URL-only input for Katana
│   ├── httpx.jsonl         # HTTPX live targets & technology metadata
│   ├── endpoints.txt       # Katana crawled endpoints
│   └── recon.json          # Machine-readable JSON summary for AI agents
├── nuclei_audit_20261116_165000.json
└── sast_20261116_165500/
    ├── semgrep.json
    ├── bandit.json
    ├── trufflehog.jsonl    # Secret values redacted
    └── summary.json
```

---

## 🔒 Security & Defensive Framing

All network workflows require an explicit `config/scope.json` authorization record. The
chain blocks unlisted targets, excluded hosts, private/reserved addresses by default,
disabled scanner classes, expired authorization, and unsafe full-port scans. Scanner
failures are surfaced instead of being reported as empty success. Result files are stored
with owner-only permissions; common secret-bearing fields are redacted.

The configuration does not create authorization. Copy the exact current scope, exclusions,
headers, rate limits, and automation rules from the relevant program before enabling a
feature. Never enable a scanner class merely because the binary is installed.

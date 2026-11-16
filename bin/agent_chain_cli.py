#!/usr/bin/env python3
import sys
import os
import json

# Ensure pipeline is in python path
current_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from pipeline.orchestrator import SecurityAgentChain
from pipeline.policy import SecurityChainError

def print_help():
    print("""
=============================================================
   SECURITY AGENT CHAIN — CLI ORCHESTRATOR
=============================================================
Usage:
  agent-chain scope init <program> <host>  Create a fail-closed scope file
  agent-chain scope status                 Show authorization and feature gates
  agent-chain scope check <feature> <url>  Verify a target without scanning it
  agent-chain recon <domain>          Run passive & active recon (subfinder + httpx + katana)
  agent-chain subfinder <domain>       Run scoped passive subdomain discovery
  agent-chain httpx <url|hosts.txt>    Run scoped HTTP probing
  agent-chain crawl <url> [depth]      Run scoped Katana crawling
  agent-chain ports <host> [ports]     Run scoped Naabu scanning
  agent-chain audit <url|hosts.txt>   Run nuclei vulnerability verification (medium/high/critical)
  agent-chain ffuf <url> [wordlist]    Run scoped low-rate content discovery
  agent-chain sast <path_to_code>     Run Semgrep & TruffleHog SAST code audit
  agent-chain http <file.http>        Run IntelliJ HTTP Client request payloads
  agent-chain qodana <path_to_code>   Run JetBrains Qodana static code security audit
  agent-chain burp                    Launch Burp Suite Community in background
  agent-chain status                  Verify all installed toolchain binaries
""")

def _main():
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    cmd = sys.argv[1].lower()
    chain = SecurityAgentChain()

    if cmd == "status":
        result = chain.check_status()
        print(f"[+] Toolchain ready: {result['ready']} ({result['tool_count']} tools)")
        for name, item in result["tools"].items():
            status = "✓ Ready" if item["ready"] else "✗ Missing"
            print(f"  - {name:<12}: {item['path']} ({status})")
        scope = result["scope"]
        print(f"[+] Scope: program={scope['program'] or '-'} authorized={scope['authorization_confirmed']} targets={scope['target_count']}")

    elif cmd == "scope":
        if len(sys.argv) < 3:
            print("Usage: agent-chain scope <init|status|check>")
            sys.exit(1)
        action = sys.argv[2].lower()
        if action == "status":
            print(json.dumps(chain.scope.status(), indent=2))
        elif action == "check":
            if len(sys.argv) < 5:
                print("Usage: agent-chain scope check <feature> <target>")
                sys.exit(1)
            print(json.dumps(chain.check_scope(sys.argv[4], sys.argv[3]), indent=2))
        elif action == "init":
            if len(sys.argv) < 5:
                print("Usage: agent-chain scope init <program> <host>")
                sys.exit(1)
            scope_path = chain.scope.path
            if scope_path.exists():
                raise SecurityChainError(f"Scope file already exists: {scope_path}")
            scope_path.parent.mkdir(parents=True, exist_ok=True)
            config = {
                "program": sys.argv[3],
                "program_url": "",
                "authorization_confirmed": False,
                "expires_on": None,
                "targets": [{"host": sys.argv[4], "include_subdomains": False, "path_prefixes": []}],
                "excluded_hosts": [],
                "required_headers": {},
                "allowed_local_roots": [str(chain.base_dir)],
                "rate_limits": {"http_per_second": 2, "ports_per_second": 50, "max_crawl_depth": 2},
                "features": {
                    "passive_recon": False,
                    "active_recon": False,
                    "port_scan": False,
                    "nuclei": False,
                    "fuzzing": False,
                    "http_replay": False
                }
            }
            scope_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
            scope_path.chmod(0o600)
            print(f"Created locked scope file: {scope_path}")
            print("Review the program policy, then explicitly enable only permitted features.")
        else:
            raise SecurityChainError(f"Unknown scope action: {action}")

    elif cmd == "recon":
        if len(sys.argv) < 3:
            print("Error: Target domain required. Usage: agent-chain recon <target.com>")
            sys.exit(1)
        domain = sys.argv[2]
        print(f"[+] Starting automated recon pipeline for: {domain}...")
        res = chain.run_recon(domain)
        print(f"[✓] Recon finished!")
        print(f"    Subdomains found : {res['subdomains_count']}")
        print(f"    Live hosts       : {res['live_hosts_count']}")
        print(f"    Endpoints parsed : {res['endpoints_count']}")
        print(f"    Results saved to : {res['target_dir']}")

    elif cmd == "subfinder":
        if len(sys.argv) < 3:
            raise SecurityChainError("Usage: agent-chain subfinder <domain>")
        print(json.dumps(chain.run_subfinder(sys.argv[2]), indent=2))

    elif cmd == "httpx":
        if len(sys.argv) < 3:
            raise SecurityChainError("Usage: agent-chain httpx <url|hosts.txt>")
        print(json.dumps(chain.run_httpx(sys.argv[2]), indent=2))

    elif cmd == "crawl":
        if len(sys.argv) < 3:
            raise SecurityChainError("Usage: agent-chain crawl <url> [depth]")
        depth = int(sys.argv[3]) if len(sys.argv) > 3 else 2
        print(json.dumps(chain.run_katana(sys.argv[2], depth=depth), indent=2))

    elif cmd == "ports":
        if len(sys.argv) < 3:
            raise SecurityChainError("Usage: agent-chain ports <host> [ports]")
        ports = sys.argv[3] if len(sys.argv) > 3 else "100"
        print(json.dumps(chain.run_naabu(sys.argv[2], top_ports=ports), indent=2))

    elif cmd == "audit":
        if len(sys.argv) < 3:
            print("Error: Target URL or hosts file required. Usage: agent-chain audit <url|hosts.txt>")
            sys.exit(1)
        target = sys.argv[2]
        print(f"[+] Starting Nuclei vulnerability audit on: {target}...")
        res = chain.run_nuclei_audit(target)
        print(f"[✓] Audit finished! Total findings: {res['findings_count']}")
        print(f"    Output saved to: {res['output_file']}")

    elif cmd == "sast":
        if len(sys.argv) < 3:
            print("Error: Target directory required. Usage: agent-chain sast <path_to_code>")
            sys.exit(1)
        path = sys.argv[2]
        print(f"[+] Starting SAST & Secret audit on: {path}...")
        res = chain.run_sast_audit(path)
        print(f"[✓] SAST finished! Semgrep findings: {res['semgrep_findings_count']}")
        print(f"    Bandit findings : {res['bandit_findings_count']}")
        print(f"    Secret findings : {res['secret_findings_count']}")
        print(f"    Results saved to: {res['target_dir']}")

    elif cmd == "ffuf":
        if len(sys.argv) < 3:
            raise SecurityChainError("Usage: agent-chain ffuf <url> [wordlist]")
        wordlist = sys.argv[3] if len(sys.argv) > 3 else "/usr/share/wordlists/dirb/common.txt"
        print(json.dumps(chain.run_ffuf(sys.argv[2], wordlist=wordlist), indent=2))

    elif cmd == "burp":
        print("[+] Launching Burp Suite...")
        res = chain.start_burpsuite()
        print(f"[✓] Burp Suite running (PID: {res['pid']}). Proxy listening on {res['proxy_host']}:{res['proxy_port']}")

    elif cmd == "http":
        if len(sys.argv) < 3:
            print("Error: HTTP file or content required. Usage: agent-chain http <request.http>")
            sys.exit(1)
        req = sys.argv[2]
        print(f"[+] Running IntelliJ HTTP Client on: {req}...")
        res = chain.run_ijhttp(req)
        print(res["stdout"])

    elif cmd == "qodana":
        if len(sys.argv) < 3:
            print("Error: Target project directory required. Usage: agent-chain qodana <path>")
            sys.exit(1)
        path = sys.argv[2]
        print(f"[+] Running JetBrains Qodana static security analysis on: {path}...")
        res = chain.run_qodana(path)
        print(res["output"])

    else:
        print_help()
        sys.exit(1)


def main():
    try:
        _main()
    except (SecurityChainError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()

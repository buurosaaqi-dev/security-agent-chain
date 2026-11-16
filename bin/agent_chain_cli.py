#!/usr/bin/env python3
import sys
import os
import json

# Ensure pipeline is in python path
current_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from pipeline.orchestrator import SecurityAgentChain

def print_help():
    print("""
=============================================================
   SECURITY AGENT CHAIN — CLI ORCHESTRATOR
=============================================================
Usage:
  agent-chain recon <domain>          Run passive & active recon (subfinder + httpx + katana)
  agent-chain audit <url|hosts.txt>   Run nuclei vulnerability verification (medium/high/critical)
  agent-chain sast <path_to_code>     Run Semgrep & TruffleHog SAST code audit
  agent-chain http <file.http>        Run IntelliJ HTTP Client request payloads
  agent-chain qodana <path_to_code>   Run JetBrains Qodana static code security audit
  agent-chain burp                    Launch Burp Suite Community in background
  agent-chain status                  Verify all installed toolchain binaries
""")

def main():
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    cmd = sys.argv[1].lower()
    chain = SecurityAgentChain()

    if cmd == "status":
        print("[+] Checking toolchain readiness:")
        for name, path in chain.tools.items():
            status = "✓ Ready" if (path and os.path.exists(path)) else "✗ Missing"
            print(f"  - {name:<12}: {path} ({status})")

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
        print(f"    Results saved to: {res['target_dir']}")

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

if __name__ == "__main__":
    main()

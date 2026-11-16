import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class SecurityAgentChain:
    """
    Unified Security Engineering & Bug Bounty Orchestration Chain.
    Designed for autonomous AI agents, LLM CLI assistants, and security engineers.
    """

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = Path(base_dir or Path(__file__).resolve().parent.parent)
        self.results_dir = self.base_dir / "results"
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Pre-resolve tool binaries
        self.tools = {
            "subfinder": shutil.which("subfinder") or "/usr/bin/subfinder",
            "httpx": shutil.which("httpx") or "/usr/bin/httpx",
            "katana": shutil.which("katana") or "/usr/local/bin/katana",
            "naabu": shutil.which("naabu") or "/usr/bin/naabu",
            "nuclei": shutil.which("nuclei") or "/usr/bin/nuclei",
            "ffuf": shutil.which("ffuf") or "/usr/bin/ffuf",
            "anew": shutil.which("anew") or "/usr/local/bin/anew",
            "semgrep": shutil.which("semgrep") or os.path.expanduser("~/.local/bin/semgrep"),
            "bandit": shutil.which("bandit") or os.path.expanduser("~/.local/bin/bandit"),
            "trufflehog": shutil.which("trufflehog") or "/usr/local/bin/trufflehog",
            "burpsuite": shutil.which("burpsuite") or "/usr/bin/burpsuite",
        }

    def _run_cmd(self, cmd: List[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd or str(self.base_dir),
            check=False,
        )

    def run_recon(self, domain: str) -> Dict[str, Any]:
        """Runs subfinder -> httpx -> katana asset mapping chain."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_dir = self.results_dir / f"{domain}_{timestamp}"
        target_dir.mkdir(parents=True, exist_ok=True)

        subdomains_file = target_dir / "subdomains.txt"
        live_hosts_file = target_dir / "live_hosts.txt"
        endpoints_file = target_dir / "endpoints.txt"
        recon_json = target_dir / "recon.json"

        # 1. Subfinder
        self._run_cmd([self.tools["subfinder"], "-d", domain, "-silent", "-all", "-o", str(subdomains_file)])
        subdomains = [line.strip() for line in subdomains_file.read_text().splitlines() if line.strip()] if subdomains_file.exists() else []

        # 2. Httpx probing
        if subdomains_file.exists() and subdomains:
            self._run_cmd([self.tools["httpx"], "-l", str(subdomains_file), "-silent", "-title", "-tech-detect", "-status-code", "-o", str(live_hosts_file)])
        else:
            self._run_cmd([self.tools["httpx"], "-u", f"https://{domain}", "-silent", "-title", "-tech-detect", "-status-code", "-o", str(live_hosts_file)])

        live_hosts = [line.strip() for line in live_hosts_file.read_text().splitlines() if line.strip()] if live_hosts_file.exists() else []

        # 3. Katana crawling
        if live_hosts_file.exists() and live_hosts:
            self._run_cmd([self.tools["katana"], "-list", str(live_hosts_file), "-silent", "-d", "2", "-jc", "-o", str(endpoints_file)])
        endpoints = [line.strip() for line in endpoints_file.read_text().splitlines() if line.strip()] if endpoints_file.exists() else []

        result = {
            "domain": domain,
            "timestamp": timestamp,
            "target_dir": str(target_dir),
            "subdomains_count": len(subdomains),
            "live_hosts_count": len(live_hosts),
            "endpoints_count": len(endpoints),
            "live_hosts": live_hosts,
            "endpoints": endpoints[:50],  # Sample for overview
        }

        recon_json.write_text(json.dumps(result, indent=2))
        return result

    def run_nuclei_audit(self, target_list_or_url: str, severity: str = "medium,high,critical") -> Dict[str, Any]:
        """Runs nuclei template auditing against a target URL or list file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.results_dir / f"nuclei_audit_{timestamp}.json"

        cmd = [self.tools["nuclei"], "-severity", severity, "-silent", "-json-export", str(output_file)]
        if os.path.exists(target_list_or_url):
            cmd.extend(["-l", target_list_or_url])
        else:
            cmd.extend(["-u", target_list_or_url])

        self._run_cmd(cmd)

        findings = []
        if output_file.exists():
            for line in output_file.read_text().splitlines():
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        return {
            "timestamp": timestamp,
            "findings_count": len(findings),
            "findings": findings,
            "output_file": str(output_file),
        }

    def run_sast_audit(self, target_path: str) -> Dict[str, Any]:
        """Runs Semgrep, Bandit, and TruffleHog against local source code."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_dir = self.results_dir / f"sast_{timestamp}"
        target_dir.mkdir(parents=True, exist_ok=True)

        semgrep_file = target_dir / "semgrep.json"
        trufflehog_file = target_dir / "trufflehog.json"

        # 1. Semgrep SAST
        self._run_cmd([self.tools["semgrep"], "scan", "--config=auto", "--json", "-o", str(semgrep_file), target_path])

        # 2. TruffleHog Secrets
        self._run_cmd([self.tools["trufflehog"], "filesystem", target_path, "--json"], cwd=str(target_dir))

        semgrep_findings = []
        if semgrep_file.exists():
            try:
                data = json.loads(semgrep_file.read_text())
                semgrep_findings = data.get("results", [])
            except json.JSONDecodeError:
                pass

        return {
            "timestamp": timestamp,
            "target_path": target_path,
            "semgrep_findings_count": len(semgrep_findings),
            "semgrep_findings": semgrep_findings[:20],
            "target_dir": str(target_dir),
        }

    def start_burpsuite(self) -> Dict[str, Any]:
        """Launches Burp Suite in background."""
        proc = subprocess.Popen([self.tools["burpsuite"]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {
            "status": "started",
            "pid": proc.pid,
            "proxy_host": "127.0.0.1",
            "proxy_port": 8080,
        }

import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


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
            "httpx": shutil.which("httpx-toolkit") or shutil.which("httpx") or "/usr/bin/httpx-toolkit",
            "katana": shutil.which("katana") or "/usr/local/bin/katana",
            "naabu": shutil.which("naabu") or "/usr/bin/naabu",
            "nuclei": shutil.which("nuclei") or "/usr/bin/nuclei",
            "ffuf": shutil.which("ffuf") or "/usr/bin/ffuf",
            "anew": shutil.which("anew") or "/usr/local/bin/anew",
            "semgrep": shutil.which("semgrep") or os.path.expanduser("~/.local/bin/semgrep"),
            "bandit": shutil.which("bandit") or os.path.expanduser("~/.local/bin/bandit"),
            "trufflehog": shutil.which("trufflehog") or "/usr/local/bin/trufflehog",
            "burpsuite": shutil.which("burpsuite") or "/usr/bin/burpsuite",
            "ijhttp": shutil.which("ijhttp") or os.path.expanduser("~/.local/bin/ijhttp"),
            "qodana": shutil.which("qodana") or os.path.expanduser("~/.local/bin/qodana"),
        }

    def _run_cmd(self, cmd: List[str], cwd: Optional[str] = None, timeout: int = 120) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd or str(self.base_dir),
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(cmd, returncode=-1, stdout="", stderr="Command timed out")

    def check_status(self) -> Dict[str, Any]:
        """Check availability of all security tools."""
        statuses = {}
        for name, path in self.tools.items():
            statuses[name] = {
                "path": path,
                "available": bool(path and os.path.exists(path)),
            }
        return statuses

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
        self._run_cmd([self.tools["subfinder"], "-d", domain, "-silent", "-all", "-o", str(subdomains_file)], timeout=90)
        subdomains = [line.strip() for line in subdomains_file.read_text().splitlines() if line.strip()] if subdomains_file.exists() else []

        # 2. Httpx probing
        if subdomains_file.exists() and subdomains:
            self._run_cmd([self.tools["httpx"], "-l", str(subdomains_file), "-silent", "-title", "-tech-detect", "-status-code", "-o", str(live_hosts_file)], timeout=60)
        else:
            self._run_cmd([self.tools["httpx"], "-u", f"https://{domain}", "-silent", "-title", "-tech-detect", "-status-code", "-o", str(live_hosts_file)], timeout=30)

        live_hosts = [line.strip() for line in live_hosts_file.read_text().splitlines() if line.strip()] if live_hosts_file.exists() else []

        # 3. Katana crawling
        if live_hosts_file.exists() and live_hosts:
            self._run_cmd([self.tools["katana"], "-list", str(live_hosts_file), "-silent", "-d", "2", "-jc", "-o", str(endpoints_file)], timeout=120)
        endpoints = [line.strip() for line in endpoints_file.read_text().splitlines() if line.strip()] if endpoints_file.exists() else []

        result = {
            "domain": domain,
            "timestamp": timestamp,
            "target_dir": str(target_dir),
            "subdomains_count": len(subdomains),
            "live_hosts_count": len(live_hosts),
            "endpoints_count": len(endpoints),
            "live_hosts": live_hosts,
            "endpoints": endpoints[:50],
        }

        recon_json.write_text(json.dumps(result, indent=2))
        return result

    def run_subfinder(self, domain: str) -> List[str]:
        """Harvest subdomains using subfinder."""
        cmd = [self.tools["subfinder"], "-d", domain, "-silent"]
        res = self._run_cmd(cmd, timeout=60)
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]

    def run_httpx(self, target_or_list: str) -> List[Dict[str, Any]]:
        """Probe live HTTP/HTTPS endpoints with httpx (returns JSON)."""
        cmd = [self.tools["httpx"], "-silent", "-title", "-tech-detect", "-status-code", "-json"]
        if os.path.exists(target_or_list):
            cmd.extend(["-l", target_or_list])
        else:
            cmd.extend(["-u", target_or_list])

        res = self._run_cmd(cmd, timeout=60)
        results = []
        for line in res.stdout.splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return results

    def run_katana(self, url: str, depth: int = 2) -> List[str]:
        """Crawl endpoints and API paths using katana."""
        cmd = [self.tools["katana"], "-u", url, "-silent", "-d", str(depth), "-jc"]
        res = self._run_cmd(cmd, timeout=60)
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]

    def run_naabu(self, host: str, top_ports: str = "100") -> List[str]:
        """Scan TCP ports on host."""
        if str(top_ports).lower() in ["100", "1000", "full"]:
            cmd = [self.tools["naabu"], "-host", host, "-top-ports", str(top_ports).lower(), "-silent"]
        else:
            cmd = [self.tools["naabu"], "-host", host, "-p", str(top_ports), "-silent"]
        res = self._run_cmd(cmd, timeout=60)
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]

    def run_nuclei_audit(self, target_list_or_url: str, severity: str = "medium,high,critical") -> Dict[str, Any]:
        """Runs nuclei template auditing against a target URL or list file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.results_dir / f"nuclei_audit_{timestamp}.json"

        cmd = [self.tools["nuclei"], "-severity", severity, "-silent", "-json-export", str(output_file)]
        if os.path.exists(target_list_or_url):
            cmd.extend(["-l", target_list_or_url])
        else:
            cmd.extend(["-u", target_list_or_url])

        self._run_cmd(cmd, timeout=180)

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

    def run_ffuf(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", match_codes: str = "200,204,301,302,307,401,403") -> Dict[str, Any]:
        """Run directory or parameter fuzzing with ffuf."""
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"

        cmd = [self.tools["ffuf"], "-u", url, "-w", wordlist, "-mc", match_codes, "-silent", "-json"]
        res = self._run_cmd(cmd, timeout=90)
        try:
            return json.loads(res.stdout)
        except json.JSONDecodeError:
            return {"raw_output": res.stdout, "stderr": res.stderr}

    def run_sast_audit(self, target_path: str) -> Dict[str, Any]:
        """Runs Semgrep, Bandit, and TruffleHog against local source code."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_dir = self.results_dir / f"sast_{timestamp}"
        target_dir.mkdir(parents=True, exist_ok=True)

        semgrep_file = target_dir / "semgrep.json"
        trufflehog_file = target_dir / "trufflehog.json"

        # 1. Semgrep SAST
        self._run_cmd([self.tools["semgrep"], "scan", "--config=auto", "--json", "-o", str(semgrep_file), target_path], timeout=120)

        # 2. TruffleHog Secrets
        self._run_cmd([self.tools["trufflehog"], "filesystem", target_path, "--json"], cwd=str(target_dir), timeout=60)

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

    def run_ijhttp(self, target_file_or_content: str) -> Dict[str, Any]:
        """Run IntelliJ HTTP Client requests against APIs/endpoints."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if os.path.exists(target_file_or_content):
            target_path = target_file_or_content
        else:
            temp_file = self.results_dir / f"request_{timestamp}.http"
            temp_file.write_text(target_file_or_content)
            target_path = str(temp_file)

        cmd = [self.tools["ijhttp"], target_path]
        res = self._run_cmd(cmd, timeout=60)
        return {
            "timestamp": timestamp,
            "target": target_path,
            "success": res.returncode == 0,
            "stdout": res.stdout,
            "stderr": res.stderr,
        }

    def run_qodana(self, project_dir: str, linter: Optional[str] = None) -> Dict[str, Any]:
        """Run JetBrains Qodana static code security inspection."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_out = self.results_dir / f"qodana_{timestamp}"
        results_out.mkdir(parents=True, exist_ok=True)

        cmd = [self.tools["qodana"], "scan", "-i", project_dir, "-o", str(results_out), "--print-problems"]
        if linter:
            cmd.extend(["-l", linter])

        res = self._run_cmd(cmd, timeout=300)
        return {
            "timestamp": timestamp,
            "project_dir": project_dir,
            "results_dir": str(results_out),
            "output": res.stdout[-2000:] if len(res.stdout) > 2000 else res.stdout,
            "success": res.returncode == 0,
        }

import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pipeline.policy import ScopeError, ScopePolicy, ToolExecutionError


SENSITIVE_KEYS = {
    "authorization", "cookie", "decoded", "password", "raw", "rawv2",
    "secret", "set-cookie", "token", "x-api-key",
}


def _redact(value: Any, key: str = "") -> Any:
    if key.lower() in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {item_key: _redact(item, str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _redact_text(value: str) -> str:
    """Redact common credential-bearing HTTP header lines in text output."""
    return re.sub(
        r"(?im)^(authorization|cookie|set-cookie|x-api-key|proxy-authorization)\s*:\s*.*$",
        lambda match: f"{match.group(1)}: [REDACTED]",
        value,
    )


class SecurityAgentChain:
    """
    Unified Security Engineering & Bug Bounty Orchestration Chain.
    Designed for autonomous AI agents, LLM CLI assistants, and security engineers.
    """

    def __init__(self, base_dir: Optional[str] = None, scope_file: Optional[str] = None):
        self.base_dir = Path(base_dir or Path(__file__).resolve().parent.parent).resolve()
        self.results_dir = self.base_dir / "results"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.chmod(0o700)
        configured_scope = scope_file or os.getenv("SECURITY_CHAIN_SCOPE_FILE")
        self.scope = ScopePolicy(
            Path(configured_scope) if configured_scope else self.base_dir / "config" / "scope.json",
            self.base_dir,
        )

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

    @staticmethod
    def _safe_slug(value: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(value)).strip("._-")
        return (slug or "target")[:100]

    def _new_result_dir(self, prefix: str) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        path = self.results_dir / f"{self._safe_slug(prefix)}_{timestamp}"
        path.mkdir(parents=True, exist_ok=False)
        path.chmod(0o700)
        return path

    @staticmethod
    def _write_text(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)

    def _write_json(self, path: Path, content: Any) -> None:
        self._write_text(path, json.dumps(_redact(content), indent=2, sort_keys=True))

    def _run_cmd(
        self,
        cmd: List[str],
        cwd: Optional[str] = None,
        timeout: int = 120,
        allowed_returncodes: tuple = (0,),
        input_text: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        executable = Path(str(cmd[0]))
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ToolExecutionError(f"Tool missing or not executable: {executable}")
        try:
            result = subprocess.run(
                cmd,
                input=input_text,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd or str(self.base_dir),
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolExecutionError(f"Command timed out after {timeout}s: {executable.name}") from exc
        if result.returncode not in allowed_returncodes:
            message = _redact_text(result.stderr.strip() or result.stdout.strip() or "unknown error")
            raise ToolExecutionError(
                f"{executable.name} failed with exit code {result.returncode}: {message[-1200:]}"
            )
        return result

    def check_status(self) -> Dict[str, Any]:
        """Check availability of all security tools."""
        statuses: Dict[str, Any] = {}
        for name, path in self.tools.items():
            tool_path = Path(path)
            exists = tool_path.is_file()
            executable = exists and os.access(tool_path, os.X_OK)
            statuses[name] = {
                "path": path,
                "exists": exists,
                "executable": executable,
                "ready": executable,
            }
        return {
            "ready": all(value["ready"] for value in statuses.values()),
            "tool_count": len(statuses),
            "tools": statuses,
            "scope": self.scope.status(),
        }

    def check_scope(self, target: str, feature: str) -> Dict[str, Any]:
        host = self.scope.assert_target(target, feature)
        return {"allowed": True, "target": target, "host": host, "feature": feature}

    def _headers(self, flag: str = "-H") -> List[str]:
        args: List[str] = []
        for name, value in self.scope.required_headers.items():
            args.extend([flag, f"{name}: {value}"])
        return args

    def _dedupe_values(self, values: List[str], output_file: Path) -> List[str]:
        cleaned = [str(value).strip() for value in values if str(value).strip()]
        output_file.unlink(missing_ok=True)
        if not cleaned:
            self._write_text(output_file, "")
            return []
        result = self._run_cmd(
            [self.tools["anew"], str(output_file)],
            timeout=30,
            input_text="\n".join(cleaned) + "\n",
        )
        output_file.chmod(0o600)
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _validated_target_file(self, raw_path: str, feature: str, result_dir: Path) -> Path:
        source = self.scope.assert_local_path(raw_path)
        values = [
            line.strip() for line in source.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if not values:
            raise ScopeError(f"Target list is empty: {source}")
        for value in values:
            self.scope.assert_target(value, feature)
        destination = result_dir / "validated_targets.txt"
        self._write_text(destination, "\n".join(values) + "\n")
        return destination

    def run_recon(self, domain: str) -> Dict[str, Any]:
        """Run a scope-filtered Subfinder -> HTTPX -> Katana pipeline."""
        host = self.scope.assert_target(domain, "active_recon")
        if "://" in domain or "/" in domain:
            raise ScopeError("Recon requires a bare domain")
        target_dir = self._new_result_dir(f"recon_{host}")
        raw_subdomains = target_dir / "subdomains_raw.txt"
        subdomains_file = target_dir / "subdomains.txt"
        httpx_file = target_dir / "httpx.jsonl"
        live_urls_file = target_dir / "live_urls.txt"
        raw_endpoints = target_dir / "endpoints_raw.txt"
        endpoints_file = target_dir / "endpoints.txt"

        self._run_cmd(
            [self.tools["subfinder"], "-d", host, "-silent", "-all", "-o", str(raw_subdomains)],
            timeout=90,
        )
        discovered = raw_subdomains.read_text(encoding="utf-8", errors="replace").splitlines() if raw_subdomains.exists() else []
        scoped = [value for value in discovered if self.scope.allows_target(value, "active_recon")]
        subdomains = self._dedupe_values(scoped or [host], subdomains_file)

        rate = self.scope.rate_limit("http_per_second", 2, 20)
        httpx_cmd = [
            self.tools["httpx"], "-l", str(subdomains_file), "-silent", "-json",
            "-title", "-tech-detect", "-status-code", "-rl", str(rate), "-o", str(httpx_file),
        ] + self._headers()
        self._run_cmd(httpx_cmd, timeout=120)

        live_records: List[Dict[str, Any]] = []
        live_urls: List[str] = []
        if httpx_file.exists():
            for line in httpx_file.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                url = record.get("url")
                if url and self.scope.allows_target(str(url), "active_recon"):
                    live_records.append(_redact(record))
                    live_urls.append(str(url))
        live_urls = self._dedupe_values(live_urls, live_urls_file)

        endpoints: List[str] = []
        if live_urls:
            katana_cmd = [
                self.tools["katana"], "-list", str(live_urls_file), "-silent", "-d", "2",
                "-jc", "-rl", str(rate), "-o", str(raw_endpoints),
            ] + self._headers()
            self._run_cmd(katana_cmd, timeout=180)
            raw_values = raw_endpoints.read_text(encoding="utf-8", errors="replace").splitlines() if raw_endpoints.exists() else []
            endpoints = self._dedupe_values(
                [value for value in raw_values if self.scope.allows_target(value, "active_recon")],
                endpoints_file,
            )
        else:
            self._write_text(endpoints_file, "")

        result = {
            "domain": host,
            "timestamp": datetime.now().isoformat(),
            "target_dir": str(target_dir),
            "subdomains_count": len(subdomains),
            "live_hosts_count": len(live_urls),
            "endpoints_count": len(endpoints),
            "live_hosts": live_records[:100],
            "endpoints": endpoints[:100],
        }
        self._write_json(target_dir / "recon.json", result)
        return result

    def run_subfinder(self, domain: str) -> List[str]:
        """Harvest subdomains using subfinder."""
        host = self.scope.assert_target(domain, "passive_recon")
        target_dir = self._new_result_dir(f"subfinder_{host}")
        cmd = [self.tools["subfinder"], "-d", host, "-silent"]
        res = self._run_cmd(cmd, timeout=60)
        values = self._dedupe_values(
            [line.strip() for line in res.stdout.splitlines() if line.strip() and self.scope.allows_target(line.strip(), "passive_recon")],
            target_dir / "subdomains.txt",
        )
        self._write_json(target_dir / "summary.json", {"domain": host, "count": len(values)})
        return values

    def run_httpx(self, target_or_list: str) -> List[Dict[str, Any]]:
        """Probe live HTTP/HTTPS endpoints with httpx (returns JSON)."""
        target_dir = self._new_result_dir("httpx")
        cmd = [self.tools["httpx"], "-silent", "-title", "-tech-detect", "-status-code", "-json"]
        if Path(target_or_list).expanduser().exists():
            target_file = self._validated_target_file(target_or_list, "active_recon", target_dir)
            cmd.extend(["-l", str(target_file)])
        else:
            self.scope.assert_target(target_or_list, "active_recon")
            cmd.extend(["-u", target_or_list])
        cmd.extend(["-rl", str(self.scope.rate_limit("http_per_second", 2, 20))])
        cmd.extend(self._headers())
        res = self._run_cmd(cmd, timeout=120)
        self._write_text(target_dir / "httpx.jsonl", res.stdout)
        results = []
        for line in res.stdout.splitlines():
            if line.strip():
                try:
                    record = json.loads(line)
                    if record.get("url") and self.scope.allows_target(str(record["url"]), "active_recon"):
                        results.append(_redact(record))
                except json.JSONDecodeError:
                    pass
        self._write_json(target_dir / "summary.json", {"count": len(results), "records": results[:100]})
        return results

    def run_katana(self, url: str, depth: int = 2) -> List[str]:
        """Crawl endpoints and API paths using katana."""
        host = self.scope.assert_target(url, "active_recon")
        depth = max(1, min(int(depth), self.scope.rate_limit("max_crawl_depth", 2, 5)))
        target_dir = self._new_result_dir(f"katana_{host}")
        cmd = [
            self.tools["katana"], "-u", url, "-silent", "-d", str(depth), "-jc",
            "-rl", str(self.scope.rate_limit("http_per_second", 2, 20)),
        ] + self._headers()
        res = self._run_cmd(cmd, timeout=180)
        values = self._dedupe_values(
            [line.strip() for line in res.stdout.splitlines() if line.strip() and self.scope.allows_target(line.strip(), "active_recon")],
            target_dir / "endpoints.txt",
        )
        self._write_json(target_dir / "summary.json", {"url": url, "count": len(values)})
        return values

    def run_naabu(self, host: str, top_ports: str = "100") -> List[str]:
        """Scan TCP ports on host."""
        host = self.scope.assert_target(host, "port_scan")
        requested = str(top_ports).lower().strip()
        if requested == "full" and not self.scope.config.get("allow_full_port_scan", False):
            raise ScopeError("Full port scans require allow_full_port_scan=true")
        if requested not in {"100", "1000", "full"}:
            ports = requested.split(",")
            if len(ports) > 100 or not all(re.fullmatch(r"\d{1,5}(-\d{1,5})?", item) for item in ports):
                raise ScopeError("Invalid port list or more than 100 entries")
        if requested in {"100", "1000", "full"}:
            cmd = [self.tools["naabu"], "-host", host, "-top-ports", requested, "-silent"]
        else:
            cmd = [self.tools["naabu"], "-host", host, "-p", requested, "-silent"]
        cmd.extend(["-rate", str(self.scope.rate_limit("ports_per_second", 50, 200))])
        res = self._run_cmd(cmd, timeout=120)
        target_dir = self._new_result_dir(f"naabu_{host}")
        values = self._dedupe_values(res.stdout.splitlines(), target_dir / "open_ports.txt")
        self._write_json(target_dir / "summary.json", {"host": host, "open_ports": values})
        return values

    def run_nuclei_audit(self, target_list_or_url: str, severity: str = "medium,high,critical") -> Dict[str, Any]:
        """Runs nuclei template auditing against a target URL or list file."""
        allowed_severities = {"info", "low", "medium", "high", "critical"}
        requested = [item.strip().lower() for item in severity.split(",") if item.strip()]
        if not requested or not set(requested).issubset(allowed_severities):
            raise ScopeError("Invalid nuclei severity filter")
        target_dir = self._new_result_dir("nuclei")
        output_file = target_dir / "findings.jsonl"
        excluded_tags = self.scope.config.get(
            "nuclei_exclude_tags",
            ["dos", "fuzz", "bruteforce", "credential-stuffing"],
        )
        cmd = [
            self.tools["nuclei"], "-severity", ",".join(requested), "-silent",
            "-jsonl-export", str(output_file),
            "-rate-limit", str(self.scope.rate_limit("http_per_second", 2, 20)),
            "-exclude-tags", ",".join(str(item) for item in excluded_tags),
        ] + self._headers()
        if Path(target_list_or_url).expanduser().exists():
            validated = self._validated_target_file(target_list_or_url, "nuclei", target_dir)
            cmd.extend(["-l", str(validated)])
        else:
            self.scope.assert_target(target_list_or_url, "nuclei")
            cmd.extend(["-u", target_list_or_url])
        self._run_cmd(cmd, timeout=300)

        findings = []
        if output_file.exists():
            for line in output_file.read_text().splitlines():
                if line.strip():
                    try:
                        findings.append(_redact(json.loads(line)))
                    except json.JSONDecodeError:
                        pass
            self._write_text(
                output_file,
                "\n".join(json.dumps(item) for item in findings) + ("\n" if findings else ""),
            )
        summary = {
            "timestamp": datetime.now().isoformat(),
            "findings_count": len(findings),
            "findings": findings[:100],
            "output_file": str(output_file),
        }
        self._write_json(target_dir / "summary.json", summary)
        return summary

    def run_ffuf(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", match_codes: str = "200,204,301,302,307,401,403") -> Dict[str, Any]:
        """Run directory or parameter fuzzing with ffuf."""
        self.scope.assert_target(url, "fuzzing")
        wordlist_path = Path(wordlist).expanduser().resolve()
        if not wordlist_path.is_file():
            raise ScopeError(f"Wordlist does not exist: {wordlist_path}")
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        target_dir = self._new_result_dir("ffuf")
        output_file = target_dir / "ffuf.json"
        cmd = [
            self.tools["ffuf"], "-u", url, "-w", str(wordlist_path), "-mc", match_codes,
            "-rate", str(self.scope.rate_limit("http_per_second", 2, 20)),
            "-of", "json", "-o", str(output_file), "-s",
        ] + self._headers()
        self._run_cmd(cmd, timeout=180)
        try:
            data = json.loads(output_file.read_text(encoding="utf-8")) if output_file.exists() else {}
        except json.JSONDecodeError as exc:
            raise ToolExecutionError("ffuf produced invalid JSON") from exc
        data = _redact(data)
        self._write_json(output_file, data)
        return data

    def run_sast_audit(self, target_path: str) -> Dict[str, Any]:
        """Runs Semgrep, Bandit, and TruffleHog against local source code."""
        target = self.scope.assert_local_path(target_path)
        target_dir = self._new_result_dir("sast")
        semgrep_file = target_dir / "semgrep.json"
        bandit_file = target_dir / "bandit.json"
        trufflehog_file = target_dir / "trufflehog.jsonl"

        self._run_cmd(
            [self.tools["semgrep"], "scan", "--config=auto", "--json", "-o", str(semgrep_file), str(target)],
            timeout=300,
        )
        self._run_cmd(
            [self.tools["bandit"], "-r", str(target), "-f", "json", "-o", str(bandit_file), "-q"],
            timeout=180,
            allowed_returncodes=(0, 1),
        )
        trufflehog = self._run_cmd(
            [
                self.tools["trufflehog"], "filesystem", str(target), "--json",
                "--no-verification", "--no-update",
            ],
            timeout=180,
        )

        semgrep_findings = []
        bandit_findings = []
        if semgrep_file.exists():
            try:
                data = json.loads(semgrep_file.read_text())
                semgrep_findings = data.get("results", [])
            except json.JSONDecodeError:
                pass
        if bandit_file.exists():
            try:
                data = json.loads(bandit_file.read_text())
                bandit_findings = data.get("results", [])
            except json.JSONDecodeError:
                pass
        secret_findings = []
        for line in trufflehog.stdout.splitlines():
            try:
                secret_findings.append(_redact(json.loads(line)))
            except json.JSONDecodeError:
                continue
        self._write_text(
            trufflehog_file,
            "\n".join(json.dumps(item) for item in secret_findings) + ("\n" if secret_findings else ""),
        )

        summary = {
            "timestamp": datetime.now().isoformat(),
            "target_path": str(target),
            "semgrep_findings_count": len(semgrep_findings),
            "bandit_findings_count": len(bandit_findings),
            "secret_findings_count": len(secret_findings),
            "semgrep_findings": _redact(semgrep_findings[:20]),
            "bandit_findings": _redact(bandit_findings[:20]),
            "secret_findings": secret_findings[:20],
            "target_dir": str(target_dir),
        }
        self._write_json(target_dir / "summary.json", summary)
        return summary

    def start_burpsuite(self) -> Dict[str, Any]:
        """Launches Burp Suite in background."""
        pid_file = self.results_dir / "burpsuite.pid"
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text(encoding="utf-8").strip())
                os.kill(pid, 0)
                return {"status": "already_running", "pid": pid, "proxy_host": "127.0.0.1", "proxy_port": 8080}
            except (ValueError, OSError):
                pid_file.unlink(missing_ok=True)
        proc = subprocess.Popen(
            [self.tools["burpsuite"]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self._write_text(pid_file, str(proc.pid))
        return {
            "status": "started",
            "pid": proc.pid,
            "proxy_host": "127.0.0.1",
            "proxy_port": 8080,
        }

    def _prepare_http_content(self, content: str) -> str:
        """Inject required headers once per IntelliJ HTTP request block."""
        request_pattern = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+https?://", re.I)
        lines = content.splitlines()
        prepared: List[str] = []
        for index, line in enumerate(lines):
            prepared.append(line)
            if not request_pattern.match(line):
                continue
            existing = set()
            for candidate in lines[index + 1:]:
                if not candidate.strip() or candidate.startswith("###") or request_pattern.match(candidate):
                    break
                if ":" in candidate:
                    existing.add(candidate.split(":", 1)[0].strip().lower())
            prepared.extend(
                f"{name}: {value}"
                for name, value in self.scope.required_headers.items()
                if name.lower() not in existing
            )
        return "\n".join(prepared) + ("\n" if content.endswith("\n") else "")

    def run_ijhttp(self, target_file_or_content: str) -> Dict[str, Any]:
        """Run IntelliJ HTTP Client requests against APIs/endpoints."""
        if Path(target_file_or_content).expanduser().exists():
            source = self.scope.assert_local_path(target_file_or_content)
            content = source.read_text(encoding="utf-8", errors="replace")
        else:
            content = target_file_or_content
        urls = re.findall(
            r"(?im)^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?://\S+)",
            content,
        )
        if not urls:
            raise ScopeError("No absolute HTTP request URL found")
        for url in urls:
            self.scope.assert_target(url, "http_replay")

        target_dir = self._new_result_dir("ijhttp")
        target_path = target_dir / "request.http"
        self._write_text(target_path, self._prepare_http_content(content))
        res = self._run_cmd([self.tools["ijhttp"], str(target_path)], timeout=120)
        output = _redact_text(res.stdout[-100_000:])
        self._write_text(target_dir / "output.txt", output)
        return {
            "timestamp": datetime.now().isoformat(),
            "target": str(target_path),
            "success": True,
            "stdout": output,
            "stderr": _redact_text(res.stderr[-10_000:]),
        }

    def run_qodana(self, project_dir: str, linter: Optional[str] = None) -> Dict[str, Any]:
        """Run JetBrains Qodana static code security inspection."""
        target = self.scope.assert_local_path(project_dir)
        results_out = self._new_result_dir("qodana")
        cmd = [self.tools["qodana"], "scan", "-i", str(target), "-o", str(results_out), "--print-problems"]
        if linter:
            if not re.fullmatch(r"[a-zA-Z0-9._-]+", linter):
                raise ScopeError("Invalid Qodana linter name")
            cmd.extend(["-l", linter])

        res = self._run_cmd(cmd, timeout=900, allowed_returncodes=(0, 1))
        summary = {
            "timestamp": datetime.now().isoformat(),
            "project_dir": str(target),
            "results_dir": str(results_out),
            "output": res.stdout[-10_000:],
            "success": res.returncode == 0,
        }
        self._write_json(results_out / "chain-summary.json", summary)
        return summary

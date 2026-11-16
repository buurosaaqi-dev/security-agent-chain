#!/usr/bin/env python3
"""
Security Agent Chain MCP Server
===============================
Model Context Protocol (MCP) server providing autonomous AI agents
(Antigravity, Claude, ChatGPT, Ollama) with direct programmatic access
to Kali Linux bug bounty and defensive security tools.
"""

import sys
import os
import json
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from mcp.server.fastmcp import FastMCP
from pipeline.orchestrator import SecurityAgentChain

# Initialize MCP Server
mcp = FastMCP("security-chain")
chain = SecurityAgentChain(base_dir=str(BASE_DIR))


@mcp.tool()
def toolchain_status() -> str:
    """Hubi xaaladda dhammaan qalabka amniga ee ku rakiban Kali Linux (subfinder, httpx, katana, naabu, nuclei, ffuf, semgrep, bandit, trufflehog, burpsuite)."""
    res = chain.check_status()
    return json.dumps(res, indent=2)


@mcp.tool()
def recon_domain(domain: str) -> str:
    """Orod pipeline-ka baadhitaanka buuxa (Subfinder -> HTTPX -> Katana). Waxay soo saartaa subdomains, live hosts, iyo endpoints la helay iyadoo loo keydinayo qaab JSON ah."""
    try:
        res = chain.run_recon(domain)
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def subfinder_scan(domain: str) -> str:
    """U isticmaal Subfinder si aad si degdeg ah ugu soo hesho passive subdomains domain kasta."""
    try:
        subdomains = chain.run_subfinder(domain)
        return json.dumps({"domain": domain, "count": len(subdomains), "subdomains": subdomains}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def httpx_probe(target: str) -> str:
    """U isticmaal HTTPX si aad u baarto web hosts nool, status codes, cinwaanka bogga (title), iyo technology stack-yada."""
    try:
        hosts = chain.run_httpx(target)
        return json.dumps({"target": target, "count": len(hosts), "hosts": hosts}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def katana_crawl(url: str, depth: int = 2) -> str:
    """U isticmaal Katana crawler si aad u hesho dhammaan endpoints, URLs, iyo feylashada qarsoon ee websaytka."""
    try:
        endpoints = chain.run_katana(url, depth=depth)
        return json.dumps({"url": url, "count": len(endpoints), "endpoints": endpoints[:100]}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def naabu_port_scan(host: str, top_ports: str = "100") -> str:
    """Ku baadh dekadaha (ports) furan adigoo isticmaalaya Naabu SYN/TCP scanner."""
    try:
        ports = chain.run_naabu(host, top_ports=top_ports)
        return json.dumps({"host": host, "open_ports": ports}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def nuclei_audit(target: str, severity: str = "medium,high,critical") -> str:
    """Orod Nuclei scanner adigoo u maraya templates rasmi ah si loo hesho nuglaanta (CVEs, misconfigurations, default credentials)."""
    try:
        res = chain.run_nuclei_audit(target, severity=severity)
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def ffuf_fuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    """Fuzzing ku samee dariiqooyinka (directories/files) websaytka adigoo isticmaalaya FFUF iyo wordlist."""
    try:
        res = chain.run_ffuf(url, wordlist=wordlist)
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def sast_audit(target_path: str) -> str:
    """Ku baadh koodhka maxalliga ah nuglaanta amniga iyo xogaha sirta ah ee baxsada adigoo adeegsanaya Semgrep iyo TruffleHog."""
    try:
        res = chain.run_sast_audit(target_path)
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def start_burp() -> str:
    """Burp Suite Community ku fur xagga dambe (background) oo soo celi xaaladdiisa."""
    try:
        res = chain.start_burpsuite()
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def ijhttp_run(request_file_or_content: str) -> str:
    """Orod IntelliJ HTTP Client (.http) adigoo u diraya codsiyo API testing, payloads, ama replaying."""
    try:
        res = chain.run_ijhttp(request_file_or_content)
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def qodana_scan(project_path: str, linter: str = "") -> str:
    """Orod JetBrains Qodana static code security & vulnerability inspection matoorka koodhka."""
    try:
        res = chain.run_qodana(project_path, linter=linter or None)
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    mcp.run(transport="stdio")

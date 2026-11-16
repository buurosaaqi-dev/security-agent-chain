from setuptools import setup, find_packages

setup(
    name="security-agent-chain",
    version="1.1.0",
    description="Unified Bug Bounty and Security Toolchain for Autonomous AI Agents and Researchers",
    author="buurosaaqi-dev",
    packages=find_packages(),
    py_modules=["mcp_server"],
    entry_points={
        "console_scripts": [
            "agent-chain=bin.agent_chain_cli:main",
            "security-chain-mcp=mcp_server:main",
        ],
    },
    install_requires=[
        "mcp>=1.0.0",
    ],
    python_requires=">=3.9",
)

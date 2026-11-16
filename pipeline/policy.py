"""Fail-closed scope and authorization policy for network security tools."""

from __future__ import annotations

import ipaddress
import json
from datetime import date
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit


class SecurityChainError(RuntimeError):
    """Base exception for safe, user-facing chain failures."""


class ScopeError(SecurityChainError):
    """Raised when a target or operation is outside authorization."""


class ToolExecutionError(SecurityChainError):
    """Raised when an integrated tool fails."""


FEATURES = (
    "passive_recon",
    "active_recon",
    "port_scan",
    "nuclei",
    "fuzzing",
    "http_replay",
)


class ScopePolicy:
    """Load and enforce a HackerOne/program scope JSON document."""

    def __init__(self, path: Path, base_dir: Path):
        self.path = path.expanduser().resolve()
        self.base_dir = base_dir.resolve()
        self.config: Dict[str, Any] = {}
        self.load_error: Optional[str] = None
        self._mtime_ns: Optional[int] = None
        self._load()

    def _load(self) -> None:
        self.config = {}
        self.load_error = None
        if not self.path.exists():
            self._mtime_ns = None
            return
        try:
            self._mtime_ns = self.path.stat().st_mtime_ns
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("scope must be a JSON object")
            headers = value.get("required_headers", {})
            if not isinstance(headers, dict):
                raise ValueError("required_headers must be an object")
            if any("\n" in f"{key}{item}" or "\r" in f"{key}{item}" for key, item in headers.items()):
                raise ValueError("required_headers cannot contain newlines")
            self.config = value
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self.load_error = str(exc)

    def _refresh_if_changed(self) -> None:
        try:
            current_mtime = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            current_mtime = None
        if current_mtime != self._mtime_ns:
            self._load()

    @staticmethod
    def _expired(value: Any) -> bool:
        if not value:
            return False
        try:
            return date.fromisoformat(str(value)) < date.today()
        except ValueError:
            return True

    @property
    def features(self) -> Dict[str, bool]:
        self._refresh_if_changed()
        configured = self.config.get("features", {})
        return {name: bool(configured.get(name, False)) for name in FEATURES}

    @property
    def required_headers(self) -> Dict[str, str]:
        self._refresh_if_changed()
        return {str(key): str(value) for key, value in self.config.get("required_headers", {}).items()}

    def status(self) -> Dict[str, Any]:
        self._refresh_if_changed()
        return {
            "scope_file": str(self.path),
            "exists": self.path.exists(),
            "valid": bool(self.config) and not self.load_error,
            "load_error": self.load_error,
            "program": self.config.get("program", ""),
            "program_url": self.config.get("program_url", ""),
            "authorization_confirmed": bool(self.config.get("authorization_confirmed", False)),
            "expires_on": self.config.get("expires_on"),
            "expired": self._expired(self.config.get("expires_on")),
            "target_count": len(self.config.get("targets", [])),
            "features": self.features,
            "required_header_names": sorted(self.required_headers),
        }

    def _assert_ready(self) -> None:
        self._refresh_if_changed()
        if not self.path.exists():
            raise ScopeError(f"Scope file missing: {self.path}; run 'agent-chain scope init'")
        if self.load_error:
            raise ScopeError(f"Invalid scope file: {self.load_error}")
        if not self.config.get("authorization_confirmed", False):
            raise ScopeError("authorization_confirmed must be true")
        if self._expired(self.config.get("expires_on")):
            raise ScopeError("Authorization is expired or expires_on is invalid")
        if not self.config.get("targets"):
            raise ScopeError("No authorized targets are configured")

    @staticmethod
    def _host_and_path(target: str) -> Tuple[str, str]:
        raw = str(target).strip()
        if not raw or any(char.isspace() for char in raw):
            raise ScopeError("Target is empty or contains whitespace")
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        if parsed.username or parsed.password:
            raise ScopeError("Credentials in target URLs are not allowed")
        if not parsed.hostname:
            raise ScopeError(f"Cannot determine host from target: {target}")
        try:
            host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as exc:
            raise ScopeError(f"Invalid target hostname: {target}") from exc
        return host, parsed.path or "/"

    def _assert_not_private(self, host: str) -> None:
        if self.config.get("allow_private_targets", False):
            return
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            raise ScopeError(f"Private/local target blocked: {host}")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            raise ScopeError(f"Private/reserved IP target blocked: {host}")

    @staticmethod
    def _pattern_matches(host: str, pattern: str) -> bool:
        pattern = pattern.lower().rstrip(".")
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return host != suffix and host.endswith(f".{suffix}")
        return host == pattern

    def assert_target(self, target: str, feature: str) -> str:
        self._assert_ready()
        if feature not in FEATURES:
            raise ScopeError(f"Unknown feature gate: {feature}")
        if not self.features[feature]:
            raise ScopeError(f"Feature disabled by scope policy: {feature}")
        host, path = self._host_and_path(target)
        self._assert_not_private(host)
        for excluded in self.config.get("excluded_hosts", []):
            if self._pattern_matches(host, str(excluded)):
                raise ScopeError(f"Target explicitly excluded: {host}")
        for rule in self.config.get("targets", []):
            if not isinstance(rule, dict) or not rule.get("host"):
                continue
            allowed = str(rule["host"]).lower().rstrip(".")
            matched = host == allowed or (
                bool(rule.get("include_subdomains", False)) and host.endswith(f".{allowed}")
            )
            prefixes = rule.get("path_prefixes", [])
            if matched and (not prefixes or any(path.startswith(str(item)) for item in prefixes)):
                return host
        raise ScopeError(f"Target outside authorized scope: {host}{path}")

    def allows_target(self, target: str, feature: str) -> bool:
        try:
            self.assert_target(target, feature)
            return True
        except ScopeError:
            return False

    def assert_local_path(self, target: str) -> Path:
        self._refresh_if_changed()
        path = Path(target).expanduser().resolve()
        if not path.exists():
            raise ScopeError(f"Local path does not exist: {path}")
        roots = [self.base_dir]
        roots.extend(Path(str(item)).expanduser().resolve() for item in self.config.get("allowed_local_roots", []))
        if not any(path == root or root in path.parents for root in roots):
            raise ScopeError(f"Local path is outside allowed_local_roots: {path}")
        return path

    def rate_limit(self, name: str, default: int, maximum: int) -> int:
        self._refresh_if_changed()
        try:
            value = int(self.config.get("rate_limits", {}).get(name, default))
        except (TypeError, ValueError):
            value = default
        return max(1, min(value, maximum))

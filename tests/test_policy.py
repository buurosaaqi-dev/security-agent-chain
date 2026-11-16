import json
import tempfile
import unittest
from pathlib import Path

from pipeline.orchestrator import SecurityAgentChain, _redact_text
from pipeline.policy import ScopeError, ScopePolicy, ToolExecutionError


class ScopePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.scope_file = self.root / "scope.json"
        self.scope_file.write_text(json.dumps({
            "program": "test-program",
            "authorization_confirmed": True,
            "targets": [{"host": "example.com", "include_subdomains": True}],
            "excluded_hosts": ["admin.example.com"],
            "required_headers": {"X-Bug-Bounty": "HackerOne-test"},
            "allowed_local_roots": [str(self.root)],
            "features": {
                "passive_recon": True,
                "active_recon": True,
                "port_scan": False,
                "nuclei": False,
                "fuzzing": False,
                "http_replay": True
            }
        }), encoding="utf-8")
        self.policy = ScopePolicy(self.scope_file, self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_and_subdomain_are_allowed(self):
        self.assertEqual(self.policy.assert_target("https://example.com/a", "active_recon"), "example.com")
        self.assertEqual(self.policy.assert_target("api.example.com", "passive_recon"), "api.example.com")

    def test_excluded_host_is_blocked(self):
        with self.assertRaises(ScopeError):
            self.policy.assert_target("admin.example.com", "active_recon")

    def test_feature_gate_is_fail_closed(self):
        with self.assertRaises(ScopeError):
            self.policy.assert_target("example.com", "nuclei")

    def test_out_of_scope_and_private_targets_are_blocked(self):
        with self.assertRaises(ScopeError):
            self.policy.assert_target("other.example", "active_recon")
        with self.assertRaises(ScopeError):
            self.policy.assert_target("127.0.0.1", "active_recon")

    def test_local_paths_require_an_allowed_root(self):
        child = self.root / "code"
        child.mkdir()
        self.assertEqual(self.policy.assert_local_path(str(child)), child.resolve())
        with self.assertRaises(ScopeError):
            self.policy.assert_local_path("/etc")

    def test_scope_file_is_reloaded_when_it_changes(self):
        dynamic_file = self.root / "dynamic.json"
        policy = ScopePolicy(dynamic_file, self.root)
        self.assertFalse(policy.status()["exists"])
        dynamic_file.write_text(self.scope_file.read_text(encoding="utf-8"), encoding="utf-8")
        self.assertTrue(policy.status()["valid"])
        self.assertEqual(policy.assert_target("example.com", "active_recon"), "example.com")


class OrchestratorSafetyTests(unittest.TestCase):
    def test_http_credentials_are_redacted_from_text_output(self):
        value = _redact_text("HTTP/1.1 200 OK\nSet-Cookie: session=secret\nbody")
        self.assertNotIn("session=secret", value)
        self.assertIn("Set-Cookie: [REDACTED]", value)

    def test_safe_slug_cannot_escape_results(self):
        self.assertEqual(SecurityAgentChain._safe_slug("../../target / name"), "target_name")

    def test_nonzero_command_raises(self):
        with tempfile.TemporaryDirectory() as folder:
            chain = SecurityAgentChain(base_dir=folder)
            with self.assertRaises(ToolExecutionError):
                chain._run_cmd(["/usr/bin/false"])

    def test_anew_is_used_for_deduplication(self):
        with tempfile.TemporaryDirectory() as folder:
            chain = SecurityAgentChain(base_dir=folder)
            output = Path(folder) / "unique.txt"
            self.assertEqual(chain._dedupe_values(["a", "a", "b"], output), ["a", "b"])
            self.assertEqual(output.read_text().splitlines(), ["a", "b"])

    def test_required_header_is_injected_only_once_per_request(self):
        with tempfile.TemporaryDirectory() as folder:
            chain = SecurityAgentChain(base_dir=folder)
            chain.scope.config = {"required_headers": {"X-Bug-Bounty": "HackerOne-test"}}
            content = (
                "GET https://example.com/one\nX-Bug-Bounty: HackerOne-test\n\n"
                "### second\nGET https://example.com/two\n\n"
            )
            prepared = chain._prepare_http_content(content)
            self.assertEqual(prepared.count("X-Bug-Bounty: HackerOne-test"), 2)


if __name__ == "__main__":
    unittest.main()

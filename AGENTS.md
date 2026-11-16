# Security Agent Chain rules

- Use this repository only for authorized defensive engineering and bug bounty programs.
- Before any network operation, call `scope_status`, then `scope_check` for the exact target and feature.
- Never edit, bypass, or weaken `config/scope.json` to make a blocked operation run.
- Treat program exclusions, required headers, rate limits, and automation restrictions as hard limits.
- Prefer local SAST and passive analysis. Run active tools only when their specific feature gate is enabled.
- Do not perform denial of service, credential attacks, social engineering, destructive payloads, persistence, or access to another person's data.
- Scanner output is a candidate, not a valid vulnerability. Reproduce minimally and obtain human review before reporting.
- Never put API keys, session cookies, access tokens, credentials, or unredacted secret findings in Git, prompts, or reports.
- Do not submit reports or contact third parties automatically.

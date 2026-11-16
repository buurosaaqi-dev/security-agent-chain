# MCP integrations

These examples connect the same fail-closed `security-chain` MCP server to AI clients.
The server uses stdio and never needs a listening network port.

1. Run `agent-chain scope init PROGRAM HOST`.
2. Review `config/scope.json` against the current program policy.
3. Set `authorization_confirmed` to `true` and enable only explicitly permitted features.
4. Merge the relevant example into the client configuration.
5. Restart the client and call `scope_status` before any network tool.

- OpenCode: merge `opencode.jsonc` into the project `opencode.jsonc`, then run `opencode mcp list`.
- Codex: merge `codex-config.toml` into a trusted project's `.codex/config.toml` or the user config.
- Claude Desktop: merge `claude-desktop.json` into the desktop MCP configuration.

Do not put API keys, cookies, access tokens, or HackerOne credentials in these files.

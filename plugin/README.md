# Legacy function metadata

`openai_tools.json` is retained as a machine-readable function catalog for clients that
build their own adapters. The old `ai-plugin.json` manifest was removed because it pointed
to a nonexistent HTTP API and had no authentication. Use the supported stdio MCP server
and the examples under `integrations/` instead.

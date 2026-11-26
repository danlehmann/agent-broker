# agent-broker

Lets AI coding agents use GitHub without ever holding a GitHub token.

A daemon under its own unix account holds the tokens. Agents run under other accounts on the
same machine and reach it through `agent-broker mcp`, an MCP server over stdio. The daemon
identifies the caller by its unix account and enforces rules that GitHub's token permissions
cannot express, such as "only branches starting with `yourname/`" and "pull requests are always
drafts".

It protects the tokens and limits what can be done with them through the broker. It does
**not** make agent-written code safe to run: anything a build executes runs with the
permissions of whoever builds it, in CI or on a desktop. Agents must run under accounts other
than your own login, without sudo and without membership in groups that amount to root
(`docker`, `lxd`, ...).

## Status

The daemon, caller identity and all tools work. The web interface and packaging do not exist
yet; until then the database is seeded with a development command (build with
`--features dev-seed`). See `docs/manual-test.md`.

## Layout

| Path | Contents |
|---|---|
| `src/dispatch.rs` | Decides about and runs every call; audit and scrubbing |
| `src/daemon.rs` | Startup checks, agent socket |
| `src/shim.rs` | The MCP server; runs as the agent and is untrusted |
| `src/github/` | The GitHub service. `local.rs` is the shim's half |
| `src/db.rs` | Database |
| `src/platform.rs` | Everything that differs between operating systems |

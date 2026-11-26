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

The daemon, caller identity, all tools and the web interface work. Packaging does not exist
yet, so the daemon's account, its run directory and its start are set up by hand, as
`docs/manual-test.md` shows. Everything after that is done in the browser.

Still missing: an HTTPS listener (the web interface is reached through a forwarded unix
socket), authenticator-app codes for logging in, and a build on macOS.

## Setting up

1. Start the daemon under its own account (see `docs/manual-test.md`).
2. On its first start it writes a one-time link to its log, with the line for `~/.ssh/config`
   that forwards the web interface to your machine. Open the link and create the first admin.
   Whoever can read that log can do this, so agent accounts must not be able to.
3. Under **Repos**, add a repo with a fine-grained token and a branch prefix.
4. Under **Linked accounts**, get a link code, run `agent-broker link` as the agent's unix
   account, type the code, and confirm on the page.
5. Give the agent's harness the MCP server `{"command": "agent-broker", "args": ["mcp"]}`.

If you are locked out, `agent-broker reset-login USERNAME`, run as the daemon's account, prints
a one-time link to set a new password.

## Layout

| Path | Contents |
|---|---|
| `src/dispatch.rs` | Decides about and runs every call; audit and scrubbing |
| `src/daemon.rs` | Startup checks, agent socket |
| `src/shim.rs` | The MCP server; runs as the agent and is untrusted |
| `src/github/` | The GitHub service. `local.rs` is the shim's half |
| `src/web/` | The web interface: sessions, pages, and what they change |
| `src/db.rs` | Database |
| `src/platform.rs` | Everything that differs between operating systems |

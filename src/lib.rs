//! Lets AI agents use external services without ever holding the credentials.
//!
//! A daemon under its own unix account holds the tokens and enforces the rules. Agents reach
//! it through the `mcp` shim, which runs as the agent and is therefore untrusted.
//!
//! Invariants every change must preserve:
//! 1. No token leaves the daemon: not in output, errors, logs, process arguments or files
//!    another account can read.
//! 2. The daemon enforces every rule itself. Talking to the socket directly gains nothing.
//! 3. A caller can only use resources of the user its unix account is linked to.
//! 4. An audit entry is written before a tool runs, or the tool does not run.
//! 5. The daemon never reads or executes anything inside a caller's files.

pub mod cli;
pub mod daemon;
pub mod db;
pub mod dispatch;
pub mod error;
pub mod github;
pub mod platform;
pub mod proto;
pub mod scrub;
pub mod shim;
pub mod spec;
pub mod web;

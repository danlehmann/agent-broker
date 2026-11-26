//! Everything that differs between operating systems.

use std::os::unix::net::UnixStream;

use nix::unistd::{Uid, User, geteuid};

/// Identifies the account on the other end of a connection. A trait so that tests can
/// impersonate several accounts; the binary always uses [`Kernel`].
pub trait Identity: Send + Sync {
    fn peer_uid(&self, stream: &UnixStream) -> std::io::Result<u32>;
    fn account_name(&self, uid: u32) -> Option<String>;
}

/// Asks the kernel and the account database.
pub struct Kernel;

impl Identity for Kernel {
    fn peer_uid(&self, stream: &UnixStream) -> std::io::Result<u32> {
        peer_uid(stream)
    }

    fn account_name(&self, uid: u32) -> Option<String> {
        User::from_uid(Uid::from_raw(uid)).ok().flatten().map(|u| u.name)
    }
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    Ok(getsockopt(stream, PeerCredentials)?.uid())
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    Ok(nix::unistd::getpeereid(stream)?.0.as_raw())
}

pub fn own_uid() -> u32 {
    geteuid().as_raw()
}

/// Home directory from the account database, not from the environment.
pub fn own_home() -> Option<std::path::PathBuf> {
    User::from_uid(geteuid()).ok().flatten().map(|u| u.dir)
}

pub fn uid_of_account(name: &str) -> Option<u32> {
    User::from_name(name).ok().flatten().map(|u| u.uid.as_raw())
}

#[cfg(target_os = "linux")]
pub const DEFAULT_RUN_DIR: &str = "/run/agent-broker";
#[cfg(target_os = "macos")]
pub const DEFAULT_RUN_DIR: &str = "/var/run/agent-broker";

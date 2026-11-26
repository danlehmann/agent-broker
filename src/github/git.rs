//! Running git in a mirror.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;

use super::GitHub;
use crate::db::RepoEntry;
use crate::error::{Error, Result, refuse};
use crate::scrub::{basic_auth, scrub};

const TIMEOUT: Duration = Duration::from_secs(900);
const MAX_CAPTURE: u64 = 4 * 1024 * 1024;

pub struct Done {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

pub struct Mirror<'a> {
    gh: &'a GitHub,
    entry: &'a RepoEntry,
    path: PathBuf,
}

impl GitHub {
    /// Opens the entry's mirror, creating it on first use. Hold the entry's lock.
    pub(super) fn mirror<'a>(&'a self, entry: &'a RepoEntry) -> Result<Mirror<'a>> {
        // Callers hold the entry's lock, as `forget` does.
        if self.is_forgotten(entry.resource_id) {
            return refuse("this repo entry was deleted");
        }
        let path = self.mirrors.join(format!("{}.git", entry.resource_id));
        let mirror = Mirror { gh: self, entry, path };
        // The remote is set last, so its presence means that setup finished.
        let url = format!("{}{}.git", self.endpoints.git, entry.full_name);
        if mirror.path.exists() {
            let current = mirror.git(&["config", "--get", "remote.origin.url"])?;
            if current.ok && current.stdout == url {
                return Ok(mirror);
            }
            return Err(Error::Internal(format!("mirror {} is broken", mirror.path.display())));
        }
        std::fs::create_dir_all(&self.mirrors)?;
        let staging = tempfile::tempdir_in(&self.mirrors)?;
        let new = Mirror { gh: self, entry, path: staging.path().to_path_buf() };
        // Without a fetch refspec only explicitly named refs are ever fetched.
        for args in
            [&["init", "--bare", "--quiet", "--template=", "."][..], &["config", "remote.origin.url", &url]]
        {
            let done = new.git(args)?;
            if !done.ok {
                return Err(Error::Internal(format!("mirror setup: {}", done.stderr)));
            }
        }
        std::fs::rename(staging.keep(), &mirror.path)?;
        Ok(mirror)
    }
}

impl Mirror<'_> {
    /// For a fork, the repo it was forked from, as git is told to read from it.
    pub fn upstream(&self) -> Option<String> {
        let entry = self.entry;
        entry.is_fork().then(|| format!("{}{}.git", self.gh.endpoints.git, entry.upstream))
    }

    /// Where a branch is read from. A fork has the agents' own branches; all others are
    /// those of the repo it was forked from.
    pub fn source(&self, branch: &str) -> String {
        match self.upstream() {
            Some(upstream) if !branch.starts_with(&self.entry.branch_prefix) => upstream,
            _ => "origin".into(),
        }
    }

    /// Runs git without the token.
    pub fn git(&self, args: &[&str]) -> Result<Done> {
        self.run(args, false)
    }

    /// Runs git with the token.
    pub fn git_auth(&self, args: &[&str]) -> Result<Done> {
        self.run(args, true)
    }

    /// Like [`Self::git_auth`], but a failure becomes a refusal.
    pub fn git_auth_or(&self, what: &str, args: &[&str]) -> Result<String> {
        let done = self.git_auth(args)?;
        if done.ok { Ok(done.stdout) } else { refuse(format!("{what}:\n{}", done.stderr)) }
    }

    pub fn resolve(&self, name: &str) -> Result<Option<String>> {
        let spec = format!("{name}^{{commit}}");
        let done = self.git(&["rev-parse", "--verify", "--quiet", &spec])?;
        Ok(Some(done.stdout).filter(|s| done.ok && super::is_commit_id(s)))
    }

    pub fn is_ancestor(&self, old: &str, new: &str) -> Result<bool> {
        Ok(self.git(&["merge-base", "--is-ancestor", old, new])?.ok)
    }

    /// Whether a ref leads to the commit. An object that merely exists may be left over from
    /// a failed upload and lack its history.
    pub fn is_reachable(&self, commit: &str) -> Result<bool> {
        let done = self.git(&["for-each-ref", "--count=1", "--contains", commit])?;
        Ok(done.ok && !done.stdout.is_empty())
    }

    fn run(&self, args: &[&str], auth: bool) -> Result<Done> {
        let mut cmd = Command::new("git");
        // No repository discovery: a broken mirror must not resolve to some parent directory.
        cmd.env_clear()
            .env("HOME", &self.gh.home)
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ALLOW_PROTOCOL", "file:https")
            .env("GIT_CEILING_DIRECTORIES", &self.gh.mirrors);
        if auth {
            // Through the environment, because arguments are visible to every account.
            let value = format!("Authorization: Basic {}", basic_auth(&self.entry.token));
            // Only for the host the mirrors come from.
            cmd.env("GIT_CONFIG_COUNT", "1")
                .env("GIT_CONFIG_KEY_0", format!("http.{}.extraheader", self.gh.endpoints.git))
                .env("GIT_CONFIG_VALUE_0", value);
        }
        cmd.arg("-C").arg(&self.path).args(["-c", "fetch.fsckObjects=true"]).args(args);
        let done = run(cmd, TIMEOUT)?;
        let clean = |s: &str| scrub(s, Some(&self.entry.token)).trim().to_string();
        Ok(Done { ok: done.ok, stdout: clean(&done.stdout), stderr: clean(&done.stderr) })
    }
}

/// Runs a command to completion or until the timeout, then kills its process group.
fn run(mut cmd: Command, timeout: Duration) -> Result<Done> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| Error::Internal(format!("cannot run git: {e}")))?;
    let out = capture(child.stdout.take());
    let err = capture(child.stderr.take());
    let deadline = Instant::now() + timeout;
    let mut pause = Duration::from_millis(1);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() > deadline {
            let _ = killpg(Pid::from_raw(child.id() as i32), Signal::SIGKILL);
            child.wait()?;
            break None;
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_millis(50));
    };
    let (stdout, stderr) = (join(out), join(err));
    match status {
        Some(status) => Ok(Done { ok: status.success(), stdout, stderr }),
        None => refuse(format!("git timed out after {} seconds", timeout.as_secs())),
    }
}

fn capture<R: Read + Send + 'static>(pipe: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = (&mut pipe).take(MAX_CAPTURE).read_to_end(&mut buf);
            // Keep draining, or git would block on a full pipe.
            let _ = std::io::copy(&mut pipe, &mut std::io::sink());
        }
        buf
    })
}

fn join(handle: std::thread::JoinHandle<Vec<u8>>) -> String {
    String::from_utf8_lossy(&handle.join().unwrap_or_default()).into_owned()
}

/// Deletes a ref when dropped, so that it goes away on failure too.
pub struct TempRef<'a> {
    pub mirror: &'a Mirror<'a>,
    pub name: String,
}

impl Drop for TempRef<'_> {
    fn drop(&mut self) {
        let _ = self.mirror.git(&["update-ref", "-d", &self.name]);
    }
}

pub fn path_str(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| Error::Internal("path is not UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_out_and_kills_the_group() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 60 & sleep 60"]);
        let start = Instant::now();
        let e = run(cmd, Duration::from_millis(100)).err().unwrap();
        assert!(e.public().contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(10));
    }
}

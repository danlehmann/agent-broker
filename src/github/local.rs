//! The shim's half of push and fetch. Runs as the agent, in the agent's checkout.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Map, Value, json};

use super::{is_commit_id, sha12};
use crate::error::{Result, refuse};
use crate::spec::{Args, bool_arg, str_arg};

pub struct Checkout {
    dir: PathBuf,
}

/// Opens the checkout named by the `workspace` argument.
pub fn checkout(args: &Args) -> Result<Checkout> {
    let dir = PathBuf::from(str_arg(args, "workspace").unwrap_or_default());
    if !dir.is_absolute() || !dir.is_dir() {
        return refuse("workspace must be the absolute path of a directory");
    }
    Ok(Checkout { dir })
}

fn valid_branch(branch: &str) -> bool {
    super::rules::check_plain_ref(branch).is_ok()
}

impl Checkout {
    fn git(&self, args: &[&str]) -> Result<std::result::Result<String, String>> {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.dir)
            .args(args)
            .stdin(Stdio::null())
            // stdout belongs to the MCP protocol, so it is always captured.
            .output();
        match out {
            Err(e) => refuse(format!("cannot run git: {e}")),
            Ok(o) if o.status.success() => Ok(Ok(String::from_utf8_lossy(&o.stdout).trim().into())),
            Ok(o) => Ok(Err(String::from_utf8_lossy(&o.stderr).trim().into())),
        }
    }

    fn resolve(&self, name: &str) -> Result<Option<String>> {
        let spec = format!("{name}^{{commit}}");
        let out = self.git(&["rev-parse", "--verify", "--quiet", "--end-of-options", &spec])?;
        Ok(out.ok().filter(|s| is_commit_id(s)))
    }

    fn set_tracking(&self, branch: &str, commit: &str) -> Result<()> {
        let name = format!("refs/remotes/origin/{branch}");
        match self.git(&["update-ref", "-m", "agent-broker", &name, commit])? {
            Ok(_) => Ok(()),
            Err(e) => refuse(format!("cannot update origin/{branch}:\n{e}")),
        }
    }

    /// What the daemon needs to know to begin a push.
    pub fn push_facts(&self, args: &Args) -> Result<Map<String, Value>> {
        let branch = str_arg(args, "branch").unwrap_or_default();
        let tip = match valid_branch(branch) {
            true => self.resolve(&format!("refs/heads/{branch}"))?,
            false => None,
        };
        let Some(tip) = tip else {
            return refuse(format!("no branch {branch} in {}", self.dir.display()));
        };
        let mut facts = Map::from_iter([("tip".to_string(), json!(tip))]);
        if bool_arg(args, "force") {
            let expected = self.resolve(&format!("refs/remotes/origin/{branch}"))?;
            facts.insert("expected".into(), json!(expected));
        }
        Ok(facts)
    }

    /// Bundles the branch without history the daemon already has.
    pub fn bundle(&self, branch: &str, basis: &[String], file: &Path) -> Result<()> {
        let mut args = vec!["bundle".to_string(), "create".into(), "--quiet".into()];
        args.extend([file.display().to_string(), format!("refs/heads/{branch}")]);
        for commit in basis.iter().filter(|c| is_commit_id(c)) {
            if self.resolve(commit)?.is_some() {
                args.push(format!("^{commit}"));
            }
        }
        match self.git(&args.iter().map(String::as_str).collect::<Vec<_>>())? {
            Ok(_) => Ok(()),
            Err(e) => refuse(format!("cannot bundle {branch}:\n{e}")),
        }
    }

    /// After a push: GitHub has `tip` now.
    pub fn pushed(&self, branch: &str, tip: &str) -> Result<()> {
        self.set_tracking(branch, tip)
    }

    /// Commits the checkout probably shares with GitHub.
    pub fn haves(&self, args: &Args) -> Result<Vec<String>> {
        let mut names = vec!["HEAD".to_string(), "refs/remotes/origin/HEAD".into()];
        for b in ["main", "master"].into_iter().chain(str_arg(args, "branch")) {
            names.push(format!("refs/remotes/origin/{b}"));
        }
        let mut haves = Vec::new();
        for name in names {
            if let Some(c) = self.resolve(&name)?
                && !haves.contains(&c)
            {
                haves.push(c);
            }
        }
        Ok(haves)
    }

    /// Stores what the daemon fetched as `origin/<branch>`.
    pub fn store(&self, local: &Map<String, Value>, bundle: Option<&Path>) -> Result<String> {
        let get = |n: &str| local.get(n).and_then(Value::as_str).unwrap_or_default();
        let (branch, tip, source) = (get("branch"), get("tip"), get("ref"));
        if !valid_branch(branch) || !is_commit_id(tip) {
            return refuse("the daemon sent an invalid reply");
        }
        let tracking = format!("refs/remotes/origin/{branch}");
        let before = self.resolve(&tracking)?;
        match bundle {
            None => self.set_tracking(branch, tip)?,
            Some(file) => {
                let spec = format!("+{source}:{tracking}");
                let file = file.display().to_string();
                let args = [
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--no-prune",
                    "--no-write-fetch-head",
                    "--no-recurse-submodules",
                    &file,
                    &spec,
                ];
                if let Err(e) = self.git(&args)? {
                    return refuse(format!("cannot store origin/{branch}:\n{e}"));
                }
            }
        }
        Ok(match before.as_deref() == Some(tip) {
            true => format!("origin/{branch} is up to date at {}", sha12(tip)),
            false => format!("origin/{branch} is now at {}", sha12(tip)),
        })
    }
}

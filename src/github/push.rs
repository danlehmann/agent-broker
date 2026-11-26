//! Pushing a branch. The shim uploads a bundle; the daemon never looks into the checkout.

use std::path::Path;

use serde_json::{Map, Value};

use super::git::{Mirror, TempRef, path_str};
use super::{GitHub, fetched_ref, is_commit_id, sha12};
use crate::db::{Db, RepoEntry};
use crate::error::{Result, refuse};
use crate::spec::{Args, bool_arg, str_arg};

/// A push between its two steps.
pub struct PendingPush {
    branch: String,
    force: bool,
    old: Option<String>,
    tip: String,
    expected: Option<String>,
    /// The default branch's commit on GitHub, if it could be fetched in the first step.
    default: Option<String>,
    /// Commits the bundle may build on.
    pub basis: Vec<String>,
    pub need_bundle: bool,
}

pub enum Begun {
    Done { text: String, tip: String },
    Pending(PendingPush),
}

pub struct Pushed {
    pub text: String,
    pub tip: String,
    /// Full old and new commit of a forced push, for the audit log.
    pub forced: Option<(String, String)>,
}

fn commit_arg(local: &Map<String, Value>, name: &str) -> Result<Option<String>> {
    match local.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if is_commit_id(s) => Ok(Some(s.to_lowercase())),
        _ => refuse(format!("'{name}' is not a commit id")),
    }
}

/// Whether the branch now at `old` is still the one the broker last pushed `last` to. The
/// name alone does not say so: the branch may have been deleted and created again.
///
/// Returns why not, if not. Whatever cannot be established counts as not.
fn still_own(
    mirror: &Mirror,
    default: Option<&str>,
    last: Option<&str>,
    old: &str,
) -> Result<Option<&'static str>> {
    let Some(last) = last else {
        return Ok(Some(
            "this tool has no record of what it last pushed there, so its history cannot be rewritten. Fetch it and add your commits on top (after that, force works again), or ask the human",
        ));
    };
    if last == old {
        return Ok(None);
    }
    let other = "no longer continues what this tool pushed there: it was re-created, rewritten or merged by someone else, so its history cannot be rewritten. Fetch it and add your commits on top, or ask the human";
    // Others may add commits on top; the caller must have seen them, which is checked later.
    if !mirror.is_ancestor(last, old)? {
        return Ok(Some(other));
    }
    // What the broker pushed was merged, so a branch that goes on from there is new work.
    // A failing git command reads as "not an ancestor", so make sure the commit is there.
    let default = match default {
        Some(default) => mirror.resolve(default)?,
        None => None,
    };
    let Some(default) = default else {
        return Ok(Some(
            "may have been merged and made anew: that cannot be ruled out, because the repo's default branch could not be fetched. Its history cannot be rewritten now; ask the human to check the default branch of the repo entry",
        ));
    };
    Ok(mirror.is_ancestor(last, &default)?.then_some(other))
}

/// The branch's commit on GitHub.
fn remote_tip(mirror: &Mirror, branch: &str) -> Result<Option<String>> {
    let name = format!("refs/heads/{branch}");
    let out = mirror.git_auth_or("cannot reach GitHub", &["ls-remote", "origin", &name])?;
    // ls-remote matches trailing path components too, so look for the exact name.
    Ok(out
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .find(|(_, r)| *r == name)
        .map(|(sha, _)| sha.to_string())
        .filter(|sha| is_commit_id(sha)))
}

impl GitHub {
    pub fn push_begin(&self, entry: &RepoEntry, args: &Args, local: &Map<String, Value>) -> Result<Begun> {
        let branch = str_arg(args, "branch").unwrap_or_default().to_string();
        let Some(tip) = commit_arg(local, "tip")? else { return refuse("missing 'tip'") };
        let expected = commit_arg(local, "expected")?;
        let lock = self.lock(entry.resource_id);
        let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let mirror = self.mirror(entry)?;

        let old = remote_tip(&mirror, &branch)?;
        if old.as_deref() == Some(&tip) {
            let text = format!("{branch} is already at {} on GitHub", sha12(&tip));
            return Ok(Begun::Done { text, tip });
        }
        let mut basis = Vec::new();
        if let Some(old) = &old {
            // Under a ref: git only accepts bundle bases that a ref leads to.
            let spec = format!("+{old}:{}", fetched_ref(&branch));
            mirror.git_auth_or(
                "cannot reach GitHub",
                &["fetch", "--no-tags", "--quiet", "--no-write-fetch-head", "origin", &spec],
            )?;
            basis.push(old.clone());
        }
        // A push works without the default branch, only with a larger bundle. A forced one
        // needs it, and only a ref fetched just now counts: an older one may be stale.
        let default_ref = fetched_ref(&entry.default_branch);
        let spec = format!("+refs/heads/{}:{default_ref}", entry.default_branch);
        let fetch = ["fetch", "--no-tags", "--quiet", "--no-write-fetch-head", "origin", &spec];
        let default = match mirror.git_auth(&fetch)?.ok {
            true => mirror.resolve(&default_ref)?,
            false => None,
        };
        if let Some(commit) = &default
            && !basis.contains(commit)
        {
            basis.push(commit.clone());
        }
        let need_bundle = !mirror.is_reachable(&tip)?;
        let force = bool_arg(args, "force");
        Ok(Begun::Pending(PendingPush { branch, force, old, tip, expected, default, basis, need_bundle }))
    }

    pub fn push_finish(
        &self,
        db: &Db,
        entry: &RepoEntry,
        call_id: &str,
        push: &PendingPush,
        bundle: Option<&Path>,
    ) -> Result<Pushed> {
        let lock = self.lock(entry.resource_id);
        let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let mirror = self.mirror(entry)?;
        let branch = &push.branch;
        let staging = TempRef { mirror: &mirror, name: format!("refs/staging/{call_id}") };

        match bundle {
            Some(bundle) => {
                let spec = format!("+refs/heads/{branch}:{}", staging.name);
                let done = mirror.git(&[
                    "fetch",
                    "--no-tags",
                    "--quiet",
                    "--no-write-fetch-head",
                    path_str(bundle)?,
                    &spec,
                ])?;
                if !done.ok {
                    return refuse(format!("the uploaded commits were not accepted:\n{}", done.stderr));
                }
            }
            None if push.need_bundle => return refuse("a bundle is required"),
            None => {
                if !mirror.git(&["update-ref", &staging.name, &push.tip])?.ok {
                    return refuse("the commit to push is gone; try again");
                }
            }
        }
        let Some(new) = mirror.resolve(&staging.name)? else {
            return refuse("the uploaded branch is not a commit");
        };
        let target = format!("{new}:refs/heads/{branch}");
        let lease = |expected: &str| format!("--force-with-lease=refs/heads/{branch}:{expected}");
        let mut forced = None;
        let mut args = vec!["push".to_string(), "--quiet".to_string()];
        match &push.old {
            None => args.push(lease("")), // must still not exist
            Some(old) if *old == new => {}
            Some(old) if mirror.is_ancestor(old, &new)? => {}
            Some(old) => {
                if !push.force {
                    return refuse(format!(
                        "{branch} on GitHub ({}) is not an ancestor of the local branch. Fetch it and merge or rebase, or use force=true, which only works for branches first pushed through this tool",
                        sha12(old)
                    ));
                }
                let Some(last_pushed) = db.created_branch(entry.resource_id, branch)? else {
                    return refuse(format!(
                        "{branch} was not first pushed through this tool, so its history cannot be rewritten; ask the human"
                    ));
                };
                let (default, last_pushed) = (push.default.as_deref(), last_pushed.as_deref());
                if let Some(why) = still_own(&mirror, default, last_pushed, old)? {
                    return refuse(format!("{branch} on GitHub ({}) {why}", sha12(old)));
                }
                // Guards against accidents only: the caller reports what it last saw.
                if push.expected.as_ref() != Some(old) {
                    return refuse(
                        "branch has changed on GitHub; fetch it, review the new commits, then retry",
                    );
                }
                args.push(lease(old));
                forced = Some((old.clone(), new.clone()));
            }
        }
        args.extend(["origin".to_string(), target]);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        mirror.git_auth_or("push failed", &args)?;

        // The push happened; nothing below may turn it into a failure.
        let _ = mirror.git(&["update-ref", &fetched_ref(branch), &new]);
        let text = match &push.old {
            None => {
                let mut text = format!("created {branch} at {}", sha12(&new));
                if let Err(e) = db.record_branch(entry.resource_id, branch, &new) {
                    eprintln!("cannot record {branch} as created: {e}");
                    text.push_str(" (but force=true will not work for it: recording it failed)");
                }
                text
            }
            Some(old) => {
                // Without this record a later force=true is refused, which is the safe side.
                if let Err(e) = db.record_push(entry.resource_id, branch, &new) {
                    eprintln!("cannot record the push to {branch}: {e}");
                }
                format!("updated {branch} {} -> {}", sha12(old), sha12(&new))
            }
        };
        Ok(Pushed { text, tip: new, forced })
    }
}

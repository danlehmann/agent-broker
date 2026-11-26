//! Pushing a branch. The shim uploads a bundle; the daemon never looks into the checkout.

use std::path::Path;

use serde_json::{Map, Value};

use super::git::{Mirror, TempRef, path_str};
use super::{GitHub, fetched_ref, is_commit_id, sha12};
use crate::db::{Db, RepoEntry};
use crate::dispatch::log;
use crate::error::{Result, refuse};
use crate::spec::{Args, bool_arg, str_arg};

/// A push between its two steps.
pub struct PendingPush {
    branch: String,
    force: bool,
    old: Option<String>,
    tip: String,
    expected: Option<String>,
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

/// Where all branches of the repo are fetched to when a forced push has to look at them.
const OTHERS: &str = "refs/others/";
/// The same for the repo a fork was forked from, where its work is merged.
const UPSTREAM: &str = "refs/upstream/";

/// Whether the branch now at `old` is still the one the broker last pushed `last` to. The
/// name alone does not say so: the branch may have been deleted and created again.
///
/// Returns why not, if not. Whatever cannot be established counts as not.
fn still_own(
    mirror: &Mirror,
    entry: &RepoEntry,
    branch: &str,
    last: Option<&str>,
    old: &str,
) -> Result<Option<String>> {
    let advice = "Its history cannot be rewritten; add your commits on top, or ask the human";
    let Some(last) = last else {
        return Ok(Some(
            "has no record here of what this tool last pushed to it, so its history cannot be rewritten now. Fetch it and add your commits on top (after that, force works again), or ask the human".into(),
        ));
    };
    if last == old {
        return Ok(None);
    }
    // Others may add commits on top; the caller must have seen them, which is checked later.
    if !mirror.is_ancestor(last, old)? {
        return Ok(Some(format!(
            "no longer continues what this tool pushed there: someone else re-created or rewrote it. {advice}"
        )));
    }
    // If what the broker pushed went into another branch, this one may be new work under an
    // old name: merged, deleted and created again from where it was merged to. Only branches
    // as they are on GitHub right now can tell, whichever branch it was merged into.
    let mut fetched = true;
    // Of the repo a fork came from only the default branch, where its work is merged: that
    // repo is someone else's and may have any number of branches.
    let base = entry.upstream_default.as_str();
    let sources = [
        (Some("origin".to_string()), format!("+refs/heads/*:{OTHERS}*")),
        (mirror.upstream(), format!("+refs/heads/{base}:{UPSTREAM}{base}")),
    ];
    for (from, spec) in sources {
        let Some(from) = from else { continue };
        let fetch = ["fetch", "--prune", "--no-tags", "--quiet", "--no-write-fetch-head", &from, &spec];
        fetched &= mirror.git_auth(&fetch)?.ok;
    }
    let holders = match fetched {
        true => mirror.git(&["for-each-ref", "--format=%(refname)", "--contains", last, OTHERS, UPSTREAM])?,
        false => return Ok(Some(format!("could not be compared with the repo's other branches. {advice}"))),
    };
    if !holders.ok {
        return Ok(Some(format!("could not be compared with the repo's other branches. {advice}")));
    }
    // Not the agents' own branches: one stacked on this one has its commits without any merge.
    let merged_into = holders.stdout.lines().find_map(|name| {
        let own = |name: &&str| *name != branch && !name.starts_with(&entry.branch_prefix);
        name.strip_prefix(OTHERS).filter(own).or(name.strip_prefix(UPSTREAM))
    });
    Ok(merged_into.map(|name| {
        format!(
            "was continued by someone else after what this tool pushed there had gone into {name}, so it may be a new branch under an old name. {advice}"
        )
    }))
}

/// The branch's commit on GitHub. Refuses the branch that is the default one there right now:
/// the entry only knows what it was when the token was last checked.
fn remote_tip(mirror: &Mirror, branch: &str) -> Result<Option<String>> {
    let name = format!("refs/heads/{branch}");
    let out =
        mirror.git_auth_or("cannot reach GitHub", &["ls-remote", "--symref", "origin", "HEAD", &name])?;
    if out.lines().any(|l| l.strip_prefix("ref: ").and_then(|l| l.split_once('\t')) == Some((&name, "HEAD")))
    {
        return refuse(format!(
            "{branch} is the repo's default branch on GitHub now. Its owner should check the token in the web UI, which updates the entry."
        ));
    }
    // ls-remote matches trailing path components too, so look for the exact name.
    Ok(out
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .find(|(sha, r)| *r == name && !sha.starts_with("ref: "))
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
        // Only makes the bundle smaller, so a missing default branch is fine.
        let base = entry.pr_base();
        let (default, from) = (fetched_ref(base), mirror.source(base));
        let spec = format!("+refs/heads/{base}:{default}");
        if mirror.git_auth(&["fetch", "--no-tags", "--quiet", "--no-write-fetch-head", &from, &spec])?.ok
            && let Some(commit) = mirror.resolve(&default)?
            && !basis.contains(&commit)
        {
            basis.push(commit);
        }
        let need_bundle = !mirror.is_reachable(&tip)?;
        let force = bool_arg(args, "force");
        Ok(Begun::Pending(PendingPush { branch, force, old, tip, expected, basis, need_bundle }))
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
        // Asked again: the default branch may have been changed since the first step.
        remote_tip(&mirror, branch)?;
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
                if let Some(why) = still_own(&mirror, entry, branch, last_pushed.as_deref(), old)? {
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
        let done = mirror.git_auth(&args)?;
        if !done.ok {
            // GitHub wants a special permission for commits that change workflow files. A
            // branch started from the repo a fork came from can carry such commits of others.
            let workflows = done.stderr.contains("workflow") && done.stderr.contains("scope");
            let advice = match (workflows, entry.is_fork()) {
                (true, true) => format!(
                    "\nThe branch has changes to workflow files that {} does not have yet. If they are not yours, ask the human to bring the fork's {} up to date with {} on GitHub (\"Sync fork\"), then push again.",
                    entry.full_name, entry.default_branch, entry.upstream
                ),
                (true, false) => {
                    "\nThe token may not change workflow files; leave them as they are, or ask the human."
                        .into()
                }
                (false, _) => String::new(),
            };
            return refuse(format!("push failed:\n{}{advice}", done.stderr));
        }

        // The push happened; nothing below may turn it into a failure.
        let _ = mirror.git(&["update-ref", &fetched_ref(branch), &new]);
        let text = match &push.old {
            None => {
                let mut text = format!("created {branch} at {}", sha12(&new));
                if let Err(e) = db.record_branch(entry.resource_id, branch, &new) {
                    log(&format!("cannot record {branch} as created: {e}"), Some(&entry.token));
                    text.push_str(" (but force=true will not work for it: recording it failed)");
                }
                text
            }
            Some(old) => {
                let mut text = format!("updated {branch} {} -> {}", sha12(old), sha12(&new));
                // The record follows the branch only while it is the broker's: pushing onto
                // a branch that someone else made anew does not make it rewritable. Whatever
                // goes wrong here leaves the record as it is, which is the safe side.
                let own = forced.is_some()
                    || match db.created_branch(entry.resource_id, branch) {
                        // Recorded before the broker kept what it pushed: start now.
                        Ok(Some(None)) => true,
                        Ok(Some(last)) => still_own(&mirror, entry, branch, last.as_deref(), old)
                            .is_ok_and(|why| why.is_none()),
                        _ => false,
                    };
                if own && let Err(e) = db.record_push(entry.resource_id, branch, &new) {
                    log(&format!("cannot record the push to {branch}: {e}"), Some(&entry.token));
                    text.push_str(" (but force=true will not work for it until its next push: recording this one failed)");
                }
                text
            }
        };
        Ok(Pushed { text, tip: new, forced })
    }
}

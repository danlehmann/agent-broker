//! Fetching a branch as a bundle.

use serde_json::{Map, Value, json};

use super::git::path_str;
use super::{GitHub, Output, fetched_ref, is_commit_id, sha12};
use crate::db::RepoEntry;
use crate::error::{Error, Result, refuse};

const MAX_HAVES: usize = 16;

impl GitHub {
    pub(super) fn fetch(
        &self,
        entry: &RepoEntry,
        branch: Option<&str>,
        local: &Map<String, Value>,
        max_blob: u64,
    ) -> Result<Output> {
        let lock = self.lock(entry.resource_id);
        let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let mirror = self.mirror(entry)?;
        let branch = match branch {
            Some(b) => b.to_string(),
            None => {
                let from = mirror.upstream().unwrap_or("origin".into());
                let out =
                    mirror.git_auth_or("cannot reach GitHub", &["ls-remote", "--symref", &from, "HEAD"])?;
                let name = out
                    .lines()
                    .filter_map(|l| l.strip_prefix("ref: refs/heads/")?.split_once('\t'))
                    .find(|(_, r)| *r == "HEAD")
                    .map(|(b, _)| b.to_string());
                match name {
                    Some(name) => name,
                    None => return refuse("the repo has no default branch"),
                }
            }
        };
        super::rules::check_plain_ref(&branch)?;

        let name = fetched_ref(&branch);
        let spec = format!("+refs/heads/{branch}:{name}");
        let from = mirror.source(&branch);
        let done =
            mirror.git_auth(&["fetch", "--no-tags", "--quiet", "--no-write-fetch-head", &from, &spec])?;
        if !done.ok {
            if done.stderr.contains("couldn't find remote ref") {
                let _ = mirror.git(&["update-ref", "-d", &name]);
            }
            return refuse(format!("cannot fetch {branch} from GitHub:\n{}", done.stderr));
        }
        let Some(tip) = mirror.resolve(&name)? else {
            return refuse(format!("{branch} is not a commit"));
        };

        let mut haves = Vec::new();
        for have in local.get("haves").and_then(Value::as_array).into_iter().flatten().take(MAX_HAVES) {
            match have.as_str() {
                Some(have) if is_commit_id(have) => {
                    if mirror.is_reachable(have)? {
                        haves.push(have.to_string());
                    }
                }
                _ => return refuse("'haves' must be commit ids"),
            }
        }
        let mut output = Output::from(format!("{branch} is at {} on GitHub", sha12(&tip)));
        output.local =
            json!({"branch": branch, "tip": tip, "ref": name}).as_object().cloned().unwrap_or_default();
        for have in &haves {
            if mirror.is_ancestor(&tip, have)? {
                return Ok(output); // the caller has it, and an empty bundle is an error
            }
        }
        let file = tempfile::NamedTempFile::new_in(&self.tmp)?;
        let mut args = vec!["bundle", "create", "--quiet", path_str(file.path())?, &name];
        let excluded: Vec<String> = haves.iter().map(|h| format!("^{h}")).collect();
        args.extend(excluded.iter().map(String::as_str));
        let done = mirror.git(&args)?;
        if !done.ok {
            return Err(Error::Internal(format!("bundle: {}", done.stderr)));
        }
        // git replaces the file, so look it up by path.
        if std::fs::metadata(file.path())?.len() > max_blob {
            return refuse(format!("{branch} is larger than the broker's limit; ask the human to raise it"));
        }
        output.blob = Some(file);
        Ok(output)
    }
}

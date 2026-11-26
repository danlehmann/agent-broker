//! Rules GitHub's own token permissions cannot express.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::db::RepoEntry;
use crate::error::{Result, refuse};

static PLAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[A-Za-z0-9][A-Za-z0-9._/-]*\z").expect("valid pattern"));

static REPO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+\z").expect("valid pattern"));

/// Branches that may be written.
pub fn check_branch(branch: &str, prefix: &str) -> Result<()> {
    let ok = !prefix.is_empty()
        && branch.starts_with(prefix)
        && branch.len() > prefix.len()
        && PLAIN.is_match(branch)
        && !branch.contains("..")
        && !branch.contains("//")
        && ![".lock", "/", "."].iter().any(|s| branch.ends_with(s));
    if ok { Ok(()) } else { refuse(format!("branch must be a plain name starting with '{prefix}'")) }
}

/// Branches and commits that may be named for reading.
pub fn check_plain_ref(name: &str) -> Result<()> {
    if PLAIN.is_match(name) && !name.contains("..") {
        Ok(())
    } else {
        refuse(format!("'{}' is not a plain branch or commit name", crate::scrub::head(name, 100)))
    }
}

/// `owner/name`, safe to put into URLs and paths.
pub fn check_repo_name(name: &str) -> Result<()> {
    let last = name.rsplit('/').next().unwrap_or("");
    if REPO.is_match(name) && !matches!(last, "." | "..") {
        Ok(())
    } else {
        refuse("repo must look like owner/name")
    }
}

/// Whether a PR comes from a branch with the entry's prefix in this very repo. The head repo
/// is absent when a fork was deleted.
/// Whether the PR's branch is in the repo itself, not in a fork. By id: after a rename
/// GitHub answers under the new name, which the stored one would not match.
pub fn same_repo(pr: &Value) -> bool {
    let id = pr["head"]["repo"]["id"].as_i64();
    id.is_some() && id == pr["base"]["repo"]["id"].as_i64()
}

pub fn check_own_pr(pr: &Value, number: i64, entry: &RepoEntry) -> Result<()> {
    let same_repo = same_repo(pr);
    let own_branch = !entry.branch_prefix.is_empty()
        && pr["head"]["ref"].as_str().is_some_and(|r| r.starts_with(&entry.branch_prefix));
    if same_repo && own_branch {
        return Ok(());
    }
    let (prefix, repo) = (&entry.branch_prefix, &entry.full_name);
    refuse(format!("PR #{number} is not from a {prefix}* branch of {repo}"))
}

#[cfg(test)]
pub(crate) fn test_entry() -> RepoEntry {
    RepoEntry {
        resource_id: 1,
        full_name: "o/r".into(),
        branch_prefix: "daniel/".into(),
        default_branch: "main".into(),
        enabled_tools: vec![],
        token: "t".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn branches() {
        for ok in ["daniel/x", "daniel/a/b", "daniel/A-1_2.3", "daniel/-x", "daniel/lock"] {
            assert!(check_branch(ok, "daniel/").is_ok(), "{ok}");
        }
        for bad in [
            "",
            "main",
            "daniel",
            "daniel/",
            "Daniel/x",
            "xdaniel/x",
            "daniel/a..b",
            "daniel/a//b",
            "daniel//",
            "daniel/a/",
            "daniel/a.",
            "daniel/a.lock",
            "daniel/a b",
            "daniel/a:b",
            "daniel/a~1",
            "daniel/a^",
            "daniel/a@{1}",
            "daniel/a\n",
            "daniel/ü",
            "daniel/*",
            "+daniel/x",
            "refs/heads/daniel/x",
            "daniel/a\0",
            "daniel/a%2e",
            "daniel/a?",
        ] {
            assert_eq!(
                check_branch(bad, "daniel/").unwrap_err().public(),
                "branch must be a plain name starting with 'daniel/'",
                "{bad:?}"
            );
        }
        assert!(check_branch("-x/y", "-x/").is_err());
        assert!(check_branch("main", "").is_err(), "an empty prefix must not mean everything");
    }

    #[test]
    fn plain_refs() {
        for ok in ["main", "a/b", "0123abc", "v1.0"] {
            assert!(check_plain_ref(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-x", "/x", ".x", "a..b", "a b", "a?x=1", "a#b", "a\n", "a%2f", "o:b"] {
            assert!(check_plain_ref(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn repo_names() {
        assert!(check_repo_name("o-1/r.x_y-z").is_ok());
        for bad in ["o", "o/", "/r", "o/r/x", "o/..", "o/.", "../r", "o/r?", "o/r\n", "o_/r", "o/r#"] {
            assert!(check_repo_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn own_pr() {
        let e = test_entry();
        let pr = |repo: Value, r: &str| json!({"head": {"repo": repo, "ref": r}, "base": {"repo": {"id": 1, "full_name": "o/r"}}});
        let check = |pr: &Value| check_own_pr(pr, 7, &e).map_err(|x| x.public().to_string());
        assert!(check(&pr(json!({"id": 1, "full_name": "o/r"}), "daniel/x")).is_ok());
        // The repo was renamed since the entry was made.
        assert!(check(&pr(json!({"id": 1, "full_name": "o/new"}), "daniel/x")).is_ok());
        for bad in [
            pr(json!({"id": 2, "full_name": "evil/r"}), "daniel/x"),
            pr(json!({"full_name": "o/r"}), "daniel/x"),
            pr(Value::Null, "daniel/x"),
            json!({"head": {"repo": {}, "ref": "daniel/x"}, "base": {}}),
            pr(json!({"id": 1, "full_name": "o/r"}), "main"),
            pr(json!({"id": 1, "full_name": "o/r"}), "xdaniel/x"),
            json!({}),
            Value::Null,
        ] {
            assert_eq!(check(&bad).unwrap_err(), "PR #7 is not from a daniel/* branch of o/r");
        }
    }
}

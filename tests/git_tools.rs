//! Push and fetch, end to end.

mod common;

use agent_broker::spec;
use common::*;
use serde_json::{Value, json};

#[test]
fn push_decision_table() {
    let w = World::new();
    let dir = w.clone("work");
    let base = git(&dir, &["rev-parse", "HEAD"]);

    // Branch does not exist.
    let one = w.commit(&dir, "one");
    assert_eq!(w.push(&dir, false), (format!("created daniel/x at {}", &one[..12]), false));
    assert_eq!(w.hub_ref("o/a", "daniel/x"), Some(one.clone()));
    assert_eq!(git(&dir, &["rev-parse", "origin/daniel/x"]), one);
    w.assert_clean();

    // Unchanged.
    let text = format!("daniel/x is already at {} on GitHub", &one[..12]);
    assert_eq!(w.push(&dir, false), (text, false));

    // Fast-forward.
    let two = w.commit(&dir, "two");
    let text = format!("updated daniel/x {} -> {}", &one[..12], &two[..12]);
    assert_eq!(w.push(&dir, false), (text, false));
    w.assert_clean();

    // Rewritten without force.
    git(&dir, &["reset", "-q", "--hard", &base]);
    let three = w.commit(&dir, "three");
    let (text, is_error) = w.push(&dir, false);
    assert!(is_error && text.contains("force=true"), "{text}");
    assert_eq!(w.hub_ref("o/a", "daniel/x"), Some(two.clone()));
    w.assert_clean();

    // Rewritten with force, on a branch created through the broker.
    let (text, is_error) = w.push(&dir, true);
    assert!(!is_error, "{text}");
    assert_eq!(w.hub_ref("o/a", "daniel/x"), Some(three.clone()));
    assert_eq!(git(&dir, &["rev-parse", "origin/daniel/x"]), three);
    w.assert_clean();
    let audit = w.broker.db.audit_rows().unwrap();
    let forced = audit.iter().find(|r| r["detail"].as_str().unwrap().contains("forced")).unwrap();
    assert!(forced["detail"].as_str().unwrap().contains(&format!("{two} -> {three}")));
}

#[test]
fn force_needs_a_broker_created_branch() {
    let w = World::new();
    let dir = w.clone("work");
    w.commit(&dir, "human");
    git(&dir, &["push", "-q", w.hub("o/a").to_str().unwrap(), "daniel/x"]);
    let human = w.hub_ref("o/a", "daniel/x");
    w.ok("github_fetch", json!({"workspace": dir, "branch": "daniel/x"}));
    git(&dir, &["reset", "-q", "--hard", "origin/main"]);
    w.commit(&dir, "agent");
    let (text, is_error) = w.push(&dir, true);
    assert!(is_error && text.contains("ask the human"), "{text}");
    assert_eq!(w.hub_ref("o/a", "daniel/x"), human);
    // A plain fast-forward of the same branch is fine.
    git(&dir, &["reset", "-q", "--hard", "origin/daniel/x"]);
    let next = w.commit(&dir, "agent on top");
    assert!(!w.push(&dir, false).1);
    assert_eq!(w.hub_ref("o/a", "daniel/x"), Some(next));
}

#[test]
fn force_does_not_drop_commits_the_checkout_has_not_seen() {
    let w = World::new();
    let dir = w.clone("work");
    w.commit(&dir, "one");
    w.push(&dir, false);
    // The human adds a commit.
    let human = w.dir.path().join("human");
    git(w.dir.path(), &["clone", "-q", w.hub("o/a").to_str().unwrap(), human.to_str().unwrap()]);
    git(&human, &["checkout", "-q", "daniel/x"]);
    let theirs = w.commit(&human, "human work");
    git(&human, &["push", "-q", "origin", "daniel/x"]);

    git(&dir, &["reset", "-q", "--hard", "origin/main"]);
    let mine = w.commit(&dir, "rebased");
    let changed = "branch has changed on GitHub; fetch it, review the new commits, then retry";
    assert_eq!(w.push(&dir, true), (changed.into(), true));
    assert_eq!(w.hub_ref("o/a", "daniel/x"), Some(theirs.clone()));
    // Another checkout that never saw the branch is refused as well.
    let fresh = w.clone("fresh");
    w.commit(&fresh, "other");
    assert_eq!(w.push(&fresh, true), (changed.into(), true));

    w.ok("github_fetch", json!({"workspace": dir, "branch": "daniel/x"}));
    assert_eq!(git(&dir, &["rev-parse", "origin/daniel/x"]), theirs);
    assert!(!w.push(&dir, true).1);
    assert_eq!(w.hub_ref("o/a", "daniel/x"), Some(mine));
}

#[test]
fn push_of_known_commits_needs_no_bundle() {
    let w = World::new();
    let dir = w.clone("work");
    let (text, is_error) = w.push(&dir, false);
    assert!(!is_error, "{text}");
    assert_eq!(w.hub_ref("o/a", "daniel/x"), w.hub_ref("o/a", "main"));
    w.assert_clean();
}

#[test]
fn push_arguments() {
    let w = World::new();
    let dir = w.clone("work");
    git(&dir, &["branch", "main", "origin/main"]);
    for branch in ["main", "daniel/", "other/x"] {
        git(&dir, &["branch", "-f", "other/x"]);
        let text = w.err("github_push", json!({"workspace": dir, "branch": branch}));
        assert!(text.contains("branch must be a plain name") || text.contains("no branch"), "{text}");
    }
    let text = w.err("github_push", json!({"workspace": "relative", "branch": "daniel/x"}));
    assert!(text.contains("absolute path"));
    let text = w.err("github_push", json!({"workspace": dir, "branch": "daniel/missing"}));
    assert!(text.contains("no branch daniel/missing"));
    let text = w.err("github_push", json!({"workspace": dir}));
    assert_eq!(text, "missing argument 'branch'");
    let text = w.err("github_push", json!({"workspace": dir, "branch": "daniel/x", "repo": "o/b"}));
    assert!(text.contains("not available"), "{text}");
}

#[test]
fn fetch() {
    let w = World::new();
    let dir = w.clone("work");
    let main = w.hub_ref("o/a", "main").unwrap();
    let text = w.ok("github_fetch", json!({"workspace": dir}));
    assert_eq!(text, format!("origin/main is up to date at {}", &main[..12]));

    let seed = w.dir.path().join("seed");
    let next = w.commit(&seed, "next");
    git(&seed, &["push", "-q", w.hub("o/a").to_str().unwrap(), "main", "main:release/1"]);
    let text = w.ok("github_fetch", json!({"workspace": dir, "branch": "main"}));
    assert_eq!(text, format!("origin/main is now at {}", &next[..12]));
    assert_eq!(git(&dir, &["rev-parse", "origin/main"]), next);
    // Known commit under a name the checkout lacks; any branch may be fetched.
    w.ok("github_fetch", json!({"workspace": dir, "branch": "release/1"}));
    assert_eq!(git(&dir, &["rev-parse", "origin/release/1"]), next);

    // A name that is a prefix of another one replaces it on GitHub.
    git(&w.hub("o/a"), &["branch", "-D", "release/1"]);
    git(&w.hub("o/a"), &["branch", "release", "main"]);
    let fresh = w.checkout("fresh");
    w.ok("github_fetch", json!({"workspace": fresh, "branch": "release"}));

    let text = w.err("github_fetch", json!({"workspace": dir, "branch": "nope"}));
    assert!(text.starts_with("cannot fetch nope from GitHub:\n"), "{text}");
    for bad in ["-x", "a..b", "--upload-pack=x", "a b", ""] {
        let text = w.err("github_fetch", json!({"workspace": dir, "branch": bad}));
        assert!(text.contains("plain branch"), "{text}");
    }
    w.assert_clean();
}

fn begin(tip: &str, branch: &str) -> Value {
    json!({"name": "github_push", "arguments": {"workspace": "/x", "branch": branch}, "local": {"tip": tip}})
}

#[test]
fn rogue_uploads() {
    let w = World::new();
    let dir = w.clone("work");
    let tip = w.commit(&dir, "one");
    git(&dir, &["branch", "evil"]);
    let bundle = |name: &str| -> Vec<u8> {
        let file = w.dir.path().join("rogue.bundle");
        git(&dir, &["bundle", "create", "-q", file.to_str().unwrap(), name]);
        std::fs::read(file).unwrap()
    };

    // Outside the prefix.
    let mut raw = Raw::connect(&w);
    let text = raw.error("tools.begin", begin(&tip, "main"), None);
    assert!(text.contains("branch must be a plain name"));
    let mut evil = begin(&tip, "daniel/x");
    evil["arguments"]["repo"] = json!("o/b");
    assert!(raw.error("tools.begin", evil, None).contains("not available"));
    // Values that would end up in git's arguments.
    for tip in ["", "--exec=x", "HEAD", "refs/heads/main"] {
        assert!(raw.error("tools.begin", begin(tip, "daniel/x"), None).contains("commit id"));
    }
    // Push through the one-step operation, and other tools through the two-step one.
    assert!(raw.error("tools.call", begin(&tip, "daniel/x"), None).contains("two steps"));
    assert!(raw.error("tools.begin", json!({"name": "github_repos"}), None).contains("one step"));

    // A bundle with another branch, garbage, and no bundle at all.
    for blob in [Some(bundle("refs/heads/evil")), Some(b"garbage".to_vec()), None] {
        let mut raw = Raw::connect(&w);
        let reply = raw.send("tools.begin", begin(&tip, "daniel/x"), None);
        let id = reply["result"]["call_id"].clone();
        assert_eq!(reply["result"]["need_blob"], true);
        raw.error("tools.finish", json!({"call_id": id}), blob.as_deref());
        // The call is over.
        raw.error("tools.finish", json!({"call_id": id}), None);
    }
    // Finishing a call that never began, or that began on another connection.
    let mut first = Raw::connect(&w);
    let id = first.send("tools.begin", begin(&tip, "daniel/x"), None)["result"]["call_id"].clone();
    assert_eq!(raw.error("tools.finish", json!({"call_id": id}), None), "no such call");
    assert!(raw.error("tools.finish", json!({"call_id": id}), Some(b"x")).contains("no upload"));
    assert_eq!(raw.read(), Value::Null, "connection closed");
    // Too large.
    w.broker.db.conn().execute("INSERT INTO settings VALUES ('max_blob', '10')", []).unwrap();
    let text = first.error("tools.finish", json!({"call_id": id}), Some(&bundle("refs/heads/daniel/x")));
    assert!(text.contains("larger than"));

    assert_eq!(w.hub_ref("o/a", "daniel/x"), None);
    assert_eq!(w.hub_ref("o/a", "evil"), None);
    assert_eq!(w.hub_ref("o/b", "daniel/x"), None);
    w.assert_clean();
}

#[test]
fn disabling_between_the_steps_stops_a_push() {
    let w = World::new();
    let dir = w.clone("work");
    let tip = w.commit(&dir, "one");
    let file = w.dir.path().join("b");
    git(&dir, &["bundle", "create", "-q", file.to_str().unwrap(), "refs/heads/daniel/x"]);
    let mut raw = Raw::connect(&w);
    let id = raw.send("tools.begin", begin(&tip, "daniel/x"), None)["result"]["call_id"].clone();
    w.broker.db.conn().execute("UPDATE resources SET enabled = 0", []).unwrap();
    raw.error("tools.finish", json!({"call_id": id}), Some(&std::fs::read(file).unwrap()));
    assert_eq!(w.hub_ref("o/a", "daniel/x"), None);
}

#[test]
fn malformed_objects_are_refused() {
    let w = World::new();
    let dir = w.clone("work");
    let blob = git(&dir, &["rev-parse", "HEAD:file"]);
    let mut tree = b"100644 .git\0".to_vec();
    tree.extend((0..blob.len()).step_by(2).map(|i| u8::from_str_radix(&blob[i..i + 2], 16).unwrap()));
    std::fs::write(dir.join("tree"), tree).unwrap();
    let tree = git(&dir, &["hash-object", "-t", "tree", "--literally", "-w", "tree"]);
    let commit = git(&dir, &["commit-tree", &tree, "-p", "HEAD", "-m", "bad"]);
    git(&dir, &["update-ref", "refs/heads/daniel/x", &commit]);
    let (text, is_error) = w.push(&dir, false);
    assert!(is_error && text.contains("not accepted"), "{text}");
    assert_eq!(w.hub_ref("o/a", "daniel/x"), None);
    w.assert_clean();
}

#[test]
fn no_audit_no_action() {
    let w = World::new();
    let dir = w.clone("work");
    w.commit(&dir, "one");
    w.broker.db.conn().execute("ALTER TABLE audit RENAME TO gone", []).unwrap();
    let (text, is_error) = w.push(&dir, false);
    assert!(is_error && text.contains("internal error"), "{text}");
    assert_eq!(w.hub_ref("o/a", "daniel/x"), None);
    assert!(w.err("github_pr_list", json!({})).contains("internal error"));
    assert!(w.api.seen.lock().unwrap().is_empty(), "GitHub was contacted");
}

#[test]
fn mirror_never_holds_the_token() {
    let w = World::new();
    let dir = w.clone("work");
    w.commit(&dir, "one");
    w.push(&dir, false);
    let out = std::process::Command::new("grep").args(["-r", "-l", TOKEN]).arg(w.mirror()).output().unwrap();
    assert_eq!(out.stdout, b"");
    assert!(spec::find("github_push").is_some());
}

#[test]
fn the_second_step_is_tied_to_the_first() {
    let w = World::new();
    let dir = w.clone("work");
    let tip = w.commit(&dir, "one");
    let file = w.dir.path().join("b");
    git(&dir, &["bundle", "create", "-q", file.to_str().unwrap(), "refs/heads/daniel/x"]);
    let bundle = std::fs::read(file).unwrap();
    let mut raw = Raw::connect(&w);
    raw.send("tools.begin", begin(&tip, "daniel/x"), None);
    assert_eq!(raw.error("tools.finish", json!({"call_id": "other"}), None), "no such call");
    assert_eq!(raw.error("tools.finish", json!({}), None), "no such call");
    let id = raw.send("tools.begin", begin(&tip, "daniel/x"), None)["result"]["call_id"].clone();
    // The repo entry is deleted and added again meanwhile: another credential, another mirror.
    let conn = w.broker.db.conn();
    conn.execute("DELETE FROM resources WHERE id = ?1", [w.alice_repo]).unwrap();
    drop(conn);
    let tools: Vec<&str> = spec::tools().iter().map(|t| t.name).collect();
    w.broker.db.add_github_repo(1, "t", "o/a", "daniel/", "main", &tools).unwrap();
    let text = raw.error("tools.finish", json!({"call_id": id}), Some(&bundle));
    assert!(text.contains("changed meanwhile"), "{text}");
    assert_eq!(w.hub_ref("o/a", "daniel/x"), None);
}

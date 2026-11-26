//! Who may do what, the API tools, and keeping the token in.

mod common;

use common::*;
use serde_json::{Value, json};

#[test]
fn each_user_sees_only_their_repos() {
    let w = World::new();
    assert!(w.ok("github_repos", json!({})).starts_with("o/a: branch prefix daniel/"));
    w.become_uid(BOB);
    let text = w.ok("github_repos", json!({}));
    assert!(text.starts_with("o/b:") && !text.contains("o/a"));
    let other = w.err("github_pr_list", json!({"repo": "o/a"}));
    let missing = w.err("github_pr_list", json!({"repo": "o/zzz"}));
    assert_eq!(other.replace("o/a", ""), missing.replace("o/zzz", ""), "existence must not leak");
}

#[test]
fn unlinked_accounts_can_only_link() {
    let w = World::new();
    w.become_uid(STRANGER);
    assert!(w.err("github_repos", json!({})).contains("not linked"));
    let mut raw = Raw::connect(&w);
    for (op, args) in [
        ("tools.list", json!({})),
        ("tools.call", json!({"name": "github_repos"})),
        ("tools.call", json!({"name": "no such tool"})),
        ("tools.begin", json!({"name": "github_push", "arguments": {}})),
    ] {
        assert!(raw.error(op, args, None).contains("not linked"), "{op}");
    }
    assert_eq!(raw.send("whoami", json!({}), None)["result"], json!({"linked": false}));
    assert!(raw.error("link", json!({"code": "0000000000"}), None).contains("link code"));

    let code = w.broker.db.new_link_code(1).unwrap();
    assert_eq!(raw.send("link", json!({"code": code}), None)["ok"], true);
    assert!(w.err("github_repos", json!({})).contains("not linked"), "unconfirmed");
    w.broker.db.confirm_link(1, STRANGER).unwrap();
    assert!(w.ok("github_repos", json!({})).starts_with("o/a"));
}

#[test]
fn root_and_the_broker_cannot_be_linked_and_guessing_is_slow() {
    let w = World::new();
    let code = w.broker.db.new_link_code(1).unwrap();
    for uid in [0, 4999] {
        w.become_uid(uid);
        let text = Raw::connect(&w).error("link", json!({"code": code}), None);
        assert_eq!(text, "this account cannot be linked");
    }
    w.become_uid(STRANGER);
    let mut raw = Raw::connect(&w);
    for _ in 0..5 {
        raw.error("link", json!({"code": "0000000000"}), None);
    }
    assert!(raw.error("link", json!({"code": code}), None).contains("too many"));
}

#[test]
fn rules_of_the_repo_entry() {
    let w = World::new();
    let db = &w.broker.db;
    db.conn().execute("UPDATE resources SET enabled_tools = 'github_pr_list'", []).unwrap();
    assert_eq!(w.err("github_pr_view", json!({"number": 1})), "github_pr_view is not enabled for o/a");
    db.conn().execute("UPDATE linked_accounts SET all_resources = 0", []).unwrap();
    assert!(w.err("github_pr_list", json!({})).contains("no repos are available"));
    assert!(w.err("github_pr_list", json!({"repo": "o/a"})).contains("not available"));
    // A prefix that covers the default branch does not open it.
    db.conn().execute("UPDATE linked_accounts SET all_resources = 1", []).unwrap();
    db.conn().execute("UPDATE resources SET enabled_tools = 'github_pr_create'", []).unwrap();
    db.conn().execute("UPDATE github_repo_entries SET branch_prefix = 'ma'", []).unwrap();
    let text = w.err("github_pr_create", json!({"branch": "main", "title": "T"}));
    assert_eq!(text, "main is the repo's default branch");
    let mut raw = Raw::connect(&w);
    db.conn().execute("UPDATE users SET disabled = 1", []).unwrap();
    assert!(raw.error("tools.list", json!({}), None).contains("not linked"), "takes effect at once");
}

#[test]
fn broken_protocol_closes_the_connection() {
    let w = World::new();
    for bad in ["garbage\n", "[]\n", "{\"op\":\"whoami\",\"blob_len\":-1}\n"] {
        let mut raw = Raw::connect(&w);
        raw.write(bad.as_bytes());
        assert_eq!(raw.read(), Value::Null);
    }
    let mut raw = Raw::connect(&w);
    assert_eq!(raw.error("nope", json!({}), None), "unknown operation");
    let text = raw.error("tools.call", json!({"name": "github_repos", "arguments": 1}), None);
    assert_eq!(text, "unknown tool");
}

fn pr(number: i64, head: &str, repo: Value) -> Value {
    json!({"number": number, "title": "T", "state": "open", "draft": true, "merged": false,
           "mergeable_state": "clean", "html_url": "http://x/1", "body": null,
           "head": {"ref": head, "sha": "abc", "repo": repo},
           "base": {"ref": "main", "repo": {"id": 1, "full_name": "o/a"}}})
}

#[test]
fn pull_requests_of_a_fork_live_in_the_repo_it_was_forked_from() {
    let w = World::new();
    // o/a is alice's fork of up/a.
    w.broker
        .db
        .conn()
        .execute("UPDATE github_repo_entries SET upstream = 'up/a', upstream_default = 'trunk'", [])
        .unwrap();
    w.api.on("POST /repos/up/a/pulls", json!({"number": 7, "html_url": "http://x/7"}));
    w.ok("github_pr_create", json!({"branch": "daniel/x", "title": "T"}));
    {
        let seen = w.api.seen.lock().unwrap();
        let body: Value = serde_json::from_str(&seen[0].body).unwrap();
        assert_eq!(
            body,
            json!({"title": "T", "body": "", "head": "o:daniel/x", "head_repo": "a", "base": "trunk",
                   "draft": true})
        );
    }
    // Hers is the PR whose branch is in her fork. Not one from another fork, and not one
    // from a branch of that name in up/a itself.
    let from = |id: i64, name: &str| {
        let mut pr = pr(1, "daniel/x", json!({"id": id, "full_name": name}));
        pr["base"]["repo"] = json!({"id": 1, "full_name": "up/a"});
        pr
    };
    w.api.on("PATCH /repos/up/a/pulls/1", json!({}));
    w.api.on("POST /repos/up/a/issues/1/comments", json!({"html_url": "http://x/c"}));
    for (id, name) in [(9, "evil/a"), (1, "up/a")] {
        w.api.on("GET /repos/up/a/pulls/1", from(id, name));
        let text = w.err("github_pr_update", json!({"number": 1, "title": "N"}));
        assert_eq!(text, "PR #1 is not from a daniel/* branch of o/a");
        assert!(w.err("github_pr_comment", json!({"number": 1, "body": "hi"})).contains("is not from"));
    }
    w.api.seen.lock().unwrap().clear();
    w.api.on("GET /repos/up/a/pulls/1", from(5, "o/a"));
    w.ok("github_pr_update", json!({"number": 1, "title": "N"}));
    w.ok("github_pr_comment", json!({"number": 1, "body": "hi"}));
    assert_eq!(w.api.writes(), ["PATCH /repos/up/a/pulls/1", "POST /repos/up/a/issues/1/comments"]);
    // The list is of up/a's PRs, cut down to hers.
    w.api.on("GET /repos/up/a/pulls", json!([from(5, "o/a"), from(9, "evil/a"), from(1, "up/a")]));
    assert_eq!(w.ok("github_pr_list", json!({})), "#1 [draft] daniel/x: T");

    // By branch, a PR is looked for where the branch is: hers in her fork, any other in up/a.
    let mut theirs = from(1, "up/a");
    theirs["number"] = json!(2);
    w.api.on("GET /repos/up/a/pulls/2", theirs.clone());
    for number in [1, 2] {
        for list in ["pulls/{}/reviews", "pulls/{}/comments", "issues/{}/comments"] {
            let list = list.replace("{}", &number.to_string());
            w.api.on(&format!("GET /repos/up/a/{list}"), json!([]));
        }
    }
    // The owner in the question does not tell the two repos apart if they have the same one.
    w.api.on("GET /repos/up/a/pulls?head=o%3Adaniel%2Fx&state=all", json!([theirs, from(5, "o/a")]));
    w.api.on("GET /repos/up/a/pulls?head=up%3Arelease&state=all", json!([from(5, "o/a"), theirs]));
    assert!(w.ok("github_pr_view", json!({"branch": "daniel/x"})).starts_with("#1 T"));
    assert!(w.ok("github_pr_view", json!({"branch": "release"})).starts_with("#2 T"));

    // CI runs are in up/a too; where her own branch is, her fork says.
    w.api.seen.lock().unwrap().clear();
    w.api.on("GET /repos/o/a/commits/daniel/x", json!({"sha": "abc"}));
    w.api.on("GET /repos/up/a/actions/runs", json!({"workflow_runs": []}));
    w.api.on("GET /repos/up/a/commits/abc/status", json!({"statuses": []}));
    w.ok("github_ci_status", json!({"branch": "daniel/x"}));
    w.api.on("GET /repos/up/a/commits/trunk", json!({"sha": "def"}));
    w.api.on("GET /repos/up/a/commits/def/status", json!({"statuses": []}));
    w.ok("github_ci_status", json!({"branch": "trunk"}));
    // A commit id is asked about in up/a, whatever it starts with.
    w.broker.db.conn().execute("UPDATE github_repo_entries SET branch_prefix = 'de'", []).unwrap();
    w.api.on("GET /repos/up/a/commits/def", json!({"sha": "def"}));
    w.ok("github_ci_status", json!({"sha": "def"}));
    let asked: Vec<String> =
        w.api.seen.lock().unwrap().iter().map(|r| r.target.split('?').next().unwrap().to_string()).collect();
    assert_eq!(
        asked,
        [
            "/repos/o/a/commits/daniel/x",
            "/repos/up/a/actions/runs",
            "/repos/up/a/commits/abc/status",
            "/repos/up/a/commits/trunk",
            "/repos/up/a/actions/runs",
            "/repos/up/a/commits/def/status",
            "/repos/up/a/commits/def",
            "/repos/up/a/actions/runs",
            "/repos/up/a/commits/def/status",
        ]
    );
}

#[test]
fn pull_requests() {
    let w = World::new();
    let own = json!({"id": 1, "full_name": "o/a"});
    w.api.on("POST /repos/o/a/pulls", json!({"number": 7, "html_url": "http://x/7"}));
    let text = w.ok("github_pr_create", json!({"branch": "daniel/x", "title": "T"}));
    assert_eq!(text, "opened draft PR #7: http://x/7");
    {
        let seen = w.api.seen.lock().unwrap();
        let body: Value = serde_json::from_str(&seen[0].body).unwrap();
        assert_eq!(
            body,
            json!({"title": "T", "body": "", "head": "daniel/x", "base": "main", "draft": true})
        );
        assert!(seen[0].headers.contains(&format!("authorization: bearer {}", TOKEN.to_lowercase())));
        assert!(seen[0].headers.contains("x-github-api-version: 2022-11-28"));
        assert!(seen[0].headers.contains("user-agent: agent-broker"));
    }
    assert!(w.err("github_pr_create", json!({"branch": "main", "title": "T"})).contains("plain name"));
    let text = w.err("github_pr_create", json!({"branch": "daniel/x", "title": "T", "base": "a..b"}));
    assert!(text.contains("plain branch"));
    w.api.seen.lock().unwrap().clear();

    w.api.on("GET /repos/o/a/pulls/1", pr(1, "daniel/x", own.clone()));
    w.api.on("GET /repos/o/a/pulls/2", pr(2, "someone/x", own.clone()));
    w.api.on("GET /repos/o/a/pulls/3", pr(3, "daniel/x", json!({"id": 2, "full_name": "evil/a"})));
    w.api.on("GET /repos/o/a/pulls/4", pr(4, "daniel/x", Value::Null));
    for n in 2..=4 {
        let refusal = format!("PR #{n} is not from a daniel/* branch of o/a");
        assert_eq!(w.err("github_pr_update", json!({"number": n, "title": "x"})), refusal);
        assert_eq!(w.err("github_pr_comment", json!({"number": n, "body": "x"})), refusal);
    }
    assert!(w.err("github_pr_update", json!({"number": 1})).contains("nothing to change"));
    assert!(
        w.err("github_pr_update", json!({"number": 1, "state": "merged"})).contains("'open' or 'closed'")
    );
    assert!(w.err("github_pr_comment", json!({"number": -1, "body": "x"})).contains("positive"));
    // With the broker's mark in front, GitHub would no longer refuse an empty comment.
    for body in ["", " \n", "[Written by an agent]", "[Written by an agent]\n\n "] {
        let text = w.err("github_pr_comment", json!({"number": 1, "body": body}));
        assert_eq!(text, "the comment has no text");
    }
    let inline = |extra: Value| {
        let mut args = json!({"number": 1, "body": "x"});
        args.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        w.err("github_pr_comment", args)
    };
    assert!(inline(json!({"reply_to": 0})).contains("'reply_to' must be positive"));
    assert!(inline(json!({"path": "f", "line": 0})).contains("'line' must be positive"));
    assert!(inline(json!({"path": "f"})).contains("both path and line"));
    assert!(inline(json!({"line": 3})).contains("both path and line"));
    assert!(inline(json!({"path": "", "line": 3})).contains("both path and line"));
    assert!(inline(json!({"reply_to": 5, "path": "f", "line": 3})).contains("not both"));
    assert!(inline(json!({"reply_to": 5, "line": 3})).contains("not both"));
    // Inline comments are held to the same rule as conversation comments.
    let refusal = "PR #2 is not from a daniel/* branch of o/a";
    assert_eq!(w.err("github_pr_comment", json!({"number": 2, "body": "x", "reply_to": 5})), refusal);
    let on_line = json!({"number": 2, "body": "x", "path": "f", "line": 3});
    assert_eq!(w.err("github_pr_comment", on_line), refusal);
    assert!(w.api.writes().is_empty());

    w.api.on("PATCH /repos/o/a/pulls/1", json!({}));
    w.api.on("POST /repos/o/a/issues/1/comments", json!({"html_url": "http://x/c"}));
    let text = w.ok("github_pr_update", json!({"number": 1, "state": "closed", "title": "N"}));
    assert_eq!(text, "updated PR #1 (title, state)");
    assert_eq!(w.ok("github_pr_comment", json!({"number": 1, "body": "hi"})), "commented: http://x/c");
    assert_eq!(w.api.writes(), ["PATCH /repos/o/a/pulls/1", "POST /repos/o/a/issues/1/comments"]);

    {
        // The mark is added once, also when the agent wrote it already.
        let seen = w.api.seen.lock().unwrap();
        let body: Value = serde_json::from_str(&seen.last().unwrap().body).unwrap();
        assert_eq!(body, json!({"body": "[Written by an agent]\n\nhi"}));
    }
    w.ok("github_pr_comment", json!({"number": 1, "body": "[Written by an agent]\n\nhi"}));
    {
        let seen = w.api.seen.lock().unwrap();
        let body: Value = serde_json::from_str(&seen.last().unwrap().body).unwrap();
        assert_eq!(body, json!({"body": "[Written by an agent]\n\nhi"}));
    }
    // Anything but the mark alone on the first line gets the mark: as the start of a link
    // definition, for one, Markdown would show nothing of it.
    for body in
        ["[Written by an agent]: http://x", " [Written by an agent]\n\nhi", "[Written by an agent] hi"]
    {
        w.ok("github_pr_comment", json!({"number": 1, "body": body}));
        let seen = w.api.seen.lock().unwrap();
        let sent: Value = serde_json::from_str(&seen.last().unwrap().body).unwrap();
        assert_eq!(sent, json!({"body": format!("[Written by an agent]\n\n{body}")}));
    }
    w.api.seen.lock().unwrap().clear();
    w.api.on("POST /repos/o/a/pulls/1/comments/5/replies", json!({"html_url": "http://x/r"}));
    let on_pr = |n: i64| format!("http://api/repos/o/a/pulls/{n}");
    w.api.on("GET /repos/o/a/pulls/comments/5", json!({"id": 5, "pull_request_url": on_pr(1)}));
    w.api.on(
        "GET /repos/o/a/pulls/comments/6",
        json!({"id": 6, "in_reply_to_id": 5, "pull_request_url": on_pr(1)}),
    );
    w.api.on("GET /repos/o/a/pulls/comments/9", json!({"id": 9, "pull_request_url": on_pr(11)}));
    // A comment of another PR, and one that does not exist.
    let text = w.err("github_pr_comment", json!({"number": 1, "body": "re", "reply_to": 9}));
    assert_eq!(text, "review comment 9 is not on PR #1");
    assert!(w.err("github_pr_comment", json!({"number": 1, "body": "re", "reply_to": 8})).contains("404"));
    assert!(w.api.writes().is_empty());
    // GitHub takes no reply to a reply, so it goes to the comment that started the thread.
    let text = w.ok("github_pr_comment", json!({"number": 1, "body": "re", "reply_to": 6}));
    assert_eq!(text, "commented: http://x/r");
    assert_eq!(w.api.writes(), ["POST /repos/o/a/pulls/1/comments/5/replies"]);
    w.api.seen.lock().unwrap().clear();
    w.api.on("POST /repos/o/a/pulls/1/comments", json!({"html_url": "http://x/l"}));
    let text = w.ok("github_pr_comment", json!({"number": 1, "body": "re", "reply_to": 5}));
    assert_eq!(text, "commented: http://x/r");
    let text = w.ok("github_pr_comment", json!({"number": 1, "body": "new", "path": "src/f.rs", "line": 3}));
    assert_eq!(text, "commented: http://x/l");
    {
        let seen = w.api.seen.lock().unwrap();
        let sent: Vec<(String, Value)> = seen
            .iter()
            .filter(|r| r.method != "GET")
            .map(|r| (r.target.clone(), serde_json::from_str(&r.body).unwrap()))
            .collect();
        assert_eq!(
            sent,
            [
                (
                    "/repos/o/a/pulls/1/comments/5/replies".to_string(),
                    json!({"body": "[Written by an agent]\n\nre"})
                ),
                (
                    "/repos/o/a/pulls/1/comments".to_string(),
                    json!({"body": "[Written by an agent]\n\nnew", "commit_id": "abc", "path": "src/f.rs", "line": 3, "side": "RIGHT"})
                ),
            ]
        );
    }

    // Not someone else's branch, and not a fork's branch of the same name.
    let fork = pr(3, "daniel/x", json!({"id": 2, "full_name": "evil/a"}));
    w.api.on("GET /repos/o/a/pulls", json!([pr(1, "daniel/x", own.clone()), pr(2, "someone/x", own), fork]));
    assert_eq!(w.ok("github_pr_list", json!({})), "#1 [draft] daniel/x: T");
    w.api.on("GET /repos/o/a/pulls", json!([]));
    assert_eq!(w.ok("github_pr_list", json!({"state": "all"})), "no PRs from daniel/* branches");
    assert_eq!(w.err("github_pr_view", json!({"branch": "daniel/none"})), "no PR for branch daniel/none");
    assert_eq!(w.err("github_pr_view", json!({})), "give number or branch");

    w.api.on(
        "GET /repos/o/a/pulls/1/reviews",
        json!([{"user": {"login": "r"}, "state": "APPROVED", "body": null}]),
    );
    w.api.on(
        "GET /repos/o/a/pulls/1/comments",
        json!([{"id": 5, "user": null, "path": "f",
             "line": null, "original_line": 3, "body": "hm"},
            {"id": 6, "user": {"login": "d"}, "path": "f", "line": 3, "in_reply_to_id": 5, "body": "ok"}]),
    );
    w.api.on("GET /repos/o/a/issues/1/comments", json!([]));
    assert_eq!(
        w.ok("github_pr_view", json!({"number": 1})),
        "#1 T\nstate: open (draft), mergeable: clean\nhead: daniel/x @ abc, base: main\n\
         url: http://x/1\n\n(no description)\n\n## Reviews\n- r: APPROVED\n\n\
         ## Review comments\n- [5]  on f:3:\nhm\n- [6] (reply to 5) d on f:3:\nok"
    );
}

#[test]
fn pagination() {
    let w = World::new();
    let own = json!({"id": 1, "full_name": "o/a"});
    let page = |n: i64, count: i64| -> Value {
        (0..count).map(|i| pr(n * 1000 + i, "daniel/x", own.clone())).collect()
    };
    let path = |n: i64| format!("GET /repos/o/a/pulls?state=open&per_page=100&page={n}");
    w.api.on(&path(1), page(1, 100));
    w.api.on(&path(2), page(2, 30));
    assert_eq!(w.ok("github_pr_list", json!({})).lines().count(), 130);
    for n in 1..=6 {
        w.api.on(&path(n), page(n, 100));
    }
    // Exactly as many as are read: nothing is missing.
    let after = "GET /repos/o/a/pulls?state=open&per_page=1&page=501";
    w.api.on(after, json!([]));
    assert_eq!(w.ok("github_pr_list", json!({})).lines().count(), 500);
    // Stopping early is said, also when nothing of what was read matched.
    w.api.on(after, json!([pr(1, "daniel/x", own.clone())]));
    let text = w.ok("github_pr_list", json!({}));
    assert_eq!(text.lines().count(), 501);
    let note = "(only the 500 newest open PRs of the repo were searched; older ones are missing here)";
    assert_eq!(text.lines().last(), Some(note));
    let others = |n: i64| -> Value { (0..100).map(|i| pr(n * 1000 + i, "someone/x", own.clone())).collect() };
    for n in 1..=5 {
        w.api.on(&path(n), others(n));
    }
    assert_eq!(w.ok("github_pr_list", json!({})), format!("no open PRs from daniel/* branches\n{note}"));

    w.api.on("GET /repos/o/a/pulls/1", pr(1, "daniel/x", own.clone()));
    w.api.on("GET /repos/o/a/pulls/1/reviews", json!([]));
    w.api.on("GET /repos/o/a/issues/1/comments", json!([]));
    let comment = json!({"id": 5, "user": null, "path": "f", "line": 3, "body": "hm"});
    for n in 1..=5 {
        let path = format!("GET /repos/o/a/pulls/1/comments?per_page=100&page={n}");
        w.api.on(&path, Value::Array(vec![comment.clone(); 100]));
    }
    w.api.on("GET /repos/o/a/pulls/1/comments?per_page=1&page=501", json!([comment]));
    assert!(
        w.ok("github_pr_view", json!({"number": 1}))
            .ends_with("\n(only the first 500 are shown; there are more)")
    );
}

#[test]
fn ci() {
    let w = World::new();
    w.api.on("GET /repos/o/a/commits/daniel/x", json!({"sha": "abc"}));
    w.api.on("GET /repos/o/a/actions/runs", json!({"workflow_runs": []}));
    w.api.on("GET /repos/o/a/commits/abc/status", json!({"statuses": []}));
    let text = w.ok("github_ci_status", json!({"branch": "daniel/x"}));
    assert_eq!(text, "commit abc\nno workflow runs for this commit (yet)");
    w.api.on(
        "GET /repos/o/a/actions/runs",
        json!({"workflow_runs": [{"id": 9, "name": "ci",
        "event": "push", "status": "in_progress", "conclusion": null, "html_url": "http://r"}]}),
    );
    w.api.on(
        "GET /repos/o/a/actions/runs/9/jobs",
        json!({"jobs": [
        {"id": 1, "name": "a", "status": "completed", "conclusion": "success"},
        {"id": 2, "name": "b", "status": "completed", "conclusion": "failure",
         "steps": [{"name": "test", "conclusion": "failure"}, {"name": "ok", "conclusion": "success"}]}]}),
    );
    w.api.on(
        "GET /repos/o/a/commits/abc/status",
        json!({"statuses": [{"context": "ext", "state": "pending", "description": null}]}),
    );
    assert_eq!(
        w.ok("github_ci_status", json!({"branch": "daniel/x"})),
        "commit abc\nrun 9 ci (push): in_progress/ http://r\n  1 of 2 jobs succeeded or were skipped\n  \
         job 2 b: completed/failure (failed steps: test)\nstatus ext: pending"
    );
    assert_eq!(w.err("github_ci_status", json!({})), "give one of pr, branch, sha");
    assert!(w.err("github_ci_status", json!({"sha": "../../x"})).contains("plain branch"));
}

#[test]
fn one_call_makes_a_limited_number_of_requests() {
    let w = World::new();
    w.api.on("GET /repos/o/a/commits/abc", json!({"sha": "abc"}));
    // 90 runs: 30 that went well, whose jobs are not asked for, and 60 that did not.
    let runs: Vec<Value> = (0..90)
        .map(|id| json!({"id": id, "name": "ci", "conclusion": if id < 30 { "success" } else { "failure" }}))
        .collect();
    w.api.on("GET /repos/o/a/actions/runs", json!({"workflow_runs": runs}));
    for id in 0..90 {
        let failed = json!({"jobs": [{"id": id, "name": "j", "conclusion": "failure"}]});
        w.api.on(&format!("GET /repos/o/a/actions/runs/{id}/jobs"), failed);
    }
    w.api.on("GET /repos/o/a/commits/abc/status", json!({"statuses": [{"context": "ext", "state": "ok"}]}));
    let text = w.ok("github_ci_status", json!({"sha": "abc"}));
    // Every run is listed and the statuses are still read; only jobs are left out.
    assert_eq!(text.lines().filter(|l| l.starts_with("run ")).count(), 90);
    assert!(text.ends_with("status ext: ok"), "{text}");
    let with_jobs = text.lines().filter(|l| l.starts_with("  job ")).count();
    let without = text.lines().filter(|l| l.starts_with("  (jobs not listed")).count();
    assert!(with_jobs >= 40 && with_jobs + without == 60, "{with_jobs} {without}");
    assert!(w.api.seen.lock().unwrap().len() <= 60);
}

#[test]
fn logs_follow_a_redirect_without_the_token() {
    let w = World::new();
    let location = format!("Location: {}/blob?sig=1\r\n", w.storage_url);
    w.api.raw("GET /repos/o/a/actions/jobs/4/logs", 302, &location, "");
    w.storage.raw("GET /blob", 200, "", "one\ntwo\nthree");
    assert_eq!(w.ok("github_ci_logs", json!({"job_id": 4, "tail": 1})), "3 lines, last 1 shown\n3: three");
    let text = w.ok("github_ci_logs", json!({"job_id": 4, "grep": "t.o", "context": 0}));
    assert_eq!(text, "3 lines, 1 shown for /t.o/\n2: two");
    assert!(w.err("github_ci_logs", json!({"job_id": 4, "grep": "("})).starts_with("bad regex"));
    for request in w.storage.seen.lock().unwrap().iter() {
        assert!(!request.headers.contains("authorization"), "{}", request.headers);
    }
    // A target that cannot be resolved is refused in plain words.
    w.api.raw("GET /repos/o/a/actions/jobs/5/logs", 302, "Location: blob?sig=1\r\n", "");
    let text = w.err("github_ci_logs", json!({"job_id": 5}));
    assert!(text.ends_with("redirect to a target that is not supported"), "{text}");
    // The same host keeps the token, or a renamed repo could not be read.
    w.api.raw("GET /repos/o/a/pulls", 301, "Location: /moved\r\n", "");
    w.api.on("GET /moved", json!([]));
    w.ok("github_pr_list", json!({}));
    let seen = w.api.seen.lock().unwrap();
    assert!(seen.last().unwrap().headers.contains("authorization"));
}

#[test]
fn the_token_stays_in() {
    let w = World::new();
    // Header names and values come back lower-cased, so use a token that survives that.
    let token = "github_pat_abc123secret";
    w.broker.db.conn().execute("UPDATE credentials SET token = ?1", [token]).unwrap();
    w.api.raw("GET /repos/o/a/pulls", 500, "", "oops ECHO");
    let text = w.err("github_pr_list", json!({}));
    assert!(text.starts_with("GitHub GET /repos/o/a/pulls: HTTP 500: oops"), "{text}");
    assert!(text.contains("bearer ***"), "{text}");
    w.api.raw("GET /repos/o/a/pulls", 200, "", "[\"ECHO\"");
    let mut texts = vec![text, w.err("github_pr_list", json!({}))];
    // An agent that somehow learnt the token must not get it into the log either.
    texts.push(w.err("github_pr_view", json!({"branch": token})));
    texts.push(w.err("github_pr_view", json!({"branch": format!("{token} x")})));
    texts.push(w.err(token, json!({})));
    w.api.raw("POST /repos/o/a/pulls", 422, "", "ECHO");
    texts.push(w.err("github_pr_create", json!({"branch": "daniel/x", "title": token})));
    // Nor the token of another repo of the same user, which has no shape to go by.
    let alice = w.broker.db.user_id("alice").unwrap().unwrap();
    let other = "otherRepoTokenWithoutShape";
    w.broker.db.add_github_repo(alice, other, "o/c", "daniel/", "main", &["github_pr_create"]).unwrap();
    w.api.raw("POST /repos/o/a/pulls", 422, "", &format!("said {other}"));
    let create = |title: &str| json!({"repo": "o/a", "branch": "daniel/x", "title": title});
    texts.push(w.err("github_pr_create", create("T")));
    texts.push(w.err("github_pr_create", create(other)));
    texts.push(w.err(other, json!({})));
    for text in texts {
        assert!(!text.contains(token) && !text.contains(other), "{text}");
    }
    let audit = serde_json::to_string(&w.broker.db.audit_rows().unwrap()).unwrap();
    assert!(!audit.contains(other), "{audit}");
    let audit = serde_json::to_string(&w.broker.db.audit_rows().unwrap()).unwrap();
    assert!(!audit.contains(token), "{audit}");
}

#[test]
fn audit_trail() {
    let w = World::new();
    w.ok("github_repos", json!({}));
    w.api.on("GET /repos/o/a/pulls", json!([]));
    w.ok("github_pr_list", json!({"state": "all"}));
    w.err("github_pr_list", json!({"state": "odd"}));
    let rows: Vec<Value> = w.broker.db.audit_rows().unwrap();
    let events: Vec<&str> = rows.iter().map(|r| r["event"].as_str().unwrap()).collect();
    assert_eq!(events, ["start", "end", "start", "end", "refused"]);
    assert_eq!(rows[2]["call_id"], rows[3]["call_id"]);
    assert_ne!(rows[0]["call_id"], rows[2]["call_id"]);
    assert_eq!(rows[2]["username"], "alice");
    assert_eq!(rows[2]["uid"], ALICE);
    assert_eq!(rows[2]["resource"], "o/a");
    assert_eq!(rows[2]["detail"], "{\"state\":\"all\"}");
    assert_eq!(rows[3]["ok"], true);
    // Abandoned uploads are closed, and refusals cannot flood the log.
    let dir = w.clone("work");
    let tip = w.commit(&dir, "one");
    let mut raw = Raw::connect(&w);
    raw.send(
        "tools.begin",
        json!({"name": "github_push", "local": {"tip": tip},
        "arguments": {"workspace": "/x", "branch": "daniel/x"}}),
        None,
    );
    drop(raw);
    let abandoned = || {
        let rows = w.broker.db.audit_rows().unwrap();
        rows.iter().any(|r| r["detail"] == "the caller disconnected")
    };
    for _ in 0..100 {
        if abandoned() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(abandoned());
    // Using the wrong form of a call is a refusal like any other.
    let before = w.broker.db.audit_rows().unwrap().len();
    let mut raw = Raw::connect(&w);
    let wrong = json!({"name": "github_push", "arguments": {"workspace": "/x", "branch": "daniel/x"}});
    assert!(raw.error("tools.call", wrong, None).contains("two steps"));
    assert!(raw.error("tools.call", json!({"name": 7}), None).contains("unknown tool"));
    let rows = w.broker.db.audit_rows().unwrap();
    assert_eq!(rows.len(), before + 2);
    assert!(rows[before..].iter().all(|r| r["event"] == "refused"));
    assert_eq!(rows[before]["detail"], "github_push needs two steps");

    // A request too large to send fails at once, not after waiting for a reply.
    let started = std::time::Instant::now();
    let text = w.err("github_pr_comment", json!({"number": 1, "body": "x".repeat(1024 * 1024)}));
    assert!(text.contains("larger than agent-broker accepts"), "{text}");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));

    let mut raw = Raw::connect(&w);
    for _ in 0..200 {
        raw.error("tools.call", json!({"name": "x"}), None);
    }
    let rows = w.broker.db.audit_rows().unwrap();
    assert!(rows.iter().filter(|r| r["event"] == "refused").count() <= 60);
}

//! The web UI, driven the way a browser would.

mod common;

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use agent_broker::web::auth::Cost;
use agent_broker::web::{Req, Resp, Web, pairs, serve};
use common::*;
use serde_json::json;

const HOST: &str = "localhost:8443";
const PASSWORD: &str = "correct horse battery";

struct Site {
    w: World,
    web: Arc<Web>,
}

/// One browser: its cookie and where its session lives.
#[derive(Default, Clone)]
struct Browser {
    cookies: String,
    base: String,
}

impl Site {
    fn new() -> Site {
        let w = World::new();
        w.broker.db.conn().execute("UPDATE users SET is_admin = 1 WHERE username = 'alice'", []).unwrap();
        let web = Arc::new(Web::new(w.broker.clone(), Cost { memory_kib: 8, passes: 1 }));
        Site { w, web }
    }

    fn request(&self, method: &str, target: &str, cookies: &str, form: &[(&str, &str)]) -> Resp {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        self.web.handle(&Req {
            method: method.into(),
            path: path.into(),
            query: pairs(query),
            host: HOST.into(),
            origin: (method == "POST").then(|| format!("http://{HOST}")),
            cookies: cookies.into(),
            form: form.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
        })
    }

    /// Gives the user a password through a one-time link, as `init` and admins do.
    fn set_password(&self, username: &str, password: &str) {
        let db = &self.w.broker.db;
        let user = db.user_id(username).unwrap().unwrap();
        let token = db.new_one_time_link(user, "setup").unwrap();
        let resp =
            self.request("POST", &format!("/setup/{token}"), "", &[("new", password), ("again", password)]);
        assert_eq!(resp.status, 303, "{}", resp.body);
    }

    fn login(&self, username: &str, password: &str) -> Browser {
        let resp = self.request("POST", "/login", "", &[("username", username), ("password", password)]);
        assert_eq!(resp.status, 303, "{}", resp.body);
        let cookie = resp.set_cookie.unwrap();
        assert!(cookie.contains("; HttpOnly") && cookie.contains("; SameSite=Strict"), "{cookie}");
        let base = resp.location.unwrap().strip_suffix("/repos").unwrap().to_string();
        Browser { cookies: cookie.split(';').next().unwrap().to_string(), base }
    }

    fn user(&self, username: &str) -> Browser {
        self.set_password(username, PASSWORD);
        self.login(username, PASSWORD)
    }

    fn get(&self, b: &Browser, page: &str) -> Resp {
        self.request("GET", &format!("{}/{page}", b.base), &b.cookies, &[])
    }

    /// The form token as the pages carry it.
    fn csrf(&self, b: &Browser) -> String {
        let body = self.get(b, "account").body;
        let at = body.find("name=\"_csrf\" value=\"").unwrap() + 20;
        body[at..at + 64].to_string()
    }

    fn post(&self, b: &Browser, action: &str, form: &[(&str, &str)]) -> Resp {
        let csrf = self.csrf(b);
        let mut form = form.to_vec();
        form.push(("_csrf", &csrf));
        self.request("POST", &format!("{}/{action}", b.base), &b.cookies, &form)
    }

    /// Posts and follows the redirect back to the page: its text, without the style sheet.
    fn done(&self, b: &Browser, action: &str, form: &[(&str, &str)]) -> String {
        let resp = self.post(b, action, form);
        assert_eq!(resp.status, 303, "{}", text(&resp.body));
        let to = resp.location.unwrap();
        text(&self.request("GET", &to, &b.cookies, &[]).body)
    }

    fn repo_id(&self, username: &str, name: &str) -> i64 {
        let db = &self.w.broker.db;
        let user = db.user_id(username).unwrap().unwrap();
        db.repo_rows(user).unwrap().iter().find(|r| r.full_name == name).unwrap().id
    }

    fn audit(&self) -> String {
        serde_json::to_string(&self.w.broker.db.audit_rows().unwrap()).unwrap()
    }
}

fn text(body: &str) -> String {
    match (body.find("<style>"), body.find("</style>")) {
        (Some(from), Some(to)) => format!("{}{}", &body[..from], &body[to + 8..]),
        _ => body.to_string(),
    }
}

#[test]
fn a_password_is_set_through_a_link_that_works_once() {
    let s = Site::new();
    let db = &s.w.broker.db;
    let alice = db.user_id("alice").unwrap().unwrap();
    let token = db.new_one_time_link(alice, "setup").unwrap();
    let link = format!("/setup/{token}");
    assert!(s.request("GET", &link, "", &[]).body.contains("Set the password of alice"));
    let differ = s.request("POST", &link, "", &[("new", PASSWORD), ("again", "something else!")]);
    assert!(differ.body.contains("the two entries differ"));
    let short = s.request("POST", &link, "", &[("new", "short"), ("again", "short")]);
    assert!(short.body.contains("at least 12 characters"));
    // Neither of these used the link up.
    let resp = s.request("POST", &link, "", &[("new", PASSWORD), ("again", PASSWORD)]);
    assert_eq!(
        (resp.status, resp.location.as_deref()),
        (303, Some("/?ok=Password%20set.%20Log%20in%20with%20it."))
    );
    assert_eq!(s.request("GET", &link, "", &[]).status, 404);
    assert_eq!(
        s.request("POST", &link, "", &[("new", "another password"), ("again", "another password")]).status,
        404
    );
    assert_eq!(s.request("GET", "/setup/nonsense", "", &[]).status, 404);
    // A newer link ends an older one.
    let old = db.new_one_time_link(alice, "reset").unwrap();
    db.new_one_time_link(alice, "reset").unwrap();
    assert_eq!(s.request("GET", &format!("/setup/{old}"), "", &[]).status, 404);
    // A link that is too old.
    let stale = db.new_one_time_link(alice, "reset").unwrap();
    db.conn().execute("UPDATE one_time_links SET expires = 1", []).unwrap();
    assert_eq!(s.request("GET", &format!("/setup/{stale}"), "", &[]).status, 404);
    s.login("alice", PASSWORD);
    assert!(!s.audit().contains(PASSWORD));
}

#[test]
fn login_takes_the_right_password_and_slows_guessing() {
    let s = Site::new();
    s.set_password("alice", PASSWORD);
    let attempt = |name: &str, password: &str| {
        s.request("POST", "/login", "", &[("username", name), ("password", password)])
    };
    // The same answer for a wrong password, an unknown user and a user without a password.
    for (name, password) in [("alice", "wrong password!"), ("nobody", PASSWORD), ("bob", PASSWORD)] {
        let resp = attempt(name, password);
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("Wrong username or password.") && resp.set_cookie.is_none(), "{name}");
    }
    // After a failure the name has to wait, even with the right password.
    let resp = attempt("alice", PASSWORD);
    assert!(resp.status == 401 && resp.body.contains("Too many attempts"), "{}", resp.body);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(attempt("alice", PASSWORD).status, 303);
    // A disabled user cannot log in.
    s.w.broker.db.conn().execute("UPDATE users SET disabled = 1 WHERE username = 'alice'", []).unwrap();
    assert_eq!(attempt("alice", PASSWORD).status, 401);
    let audit = s.audit();
    assert!(audit.contains("\"detail\":\"as nobody\"") && !audit.contains(PASSWORD), "{audit}");
}

#[test]
fn a_page_needs_the_cookie_and_the_secret_in_the_path() {
    let s = Site::new();
    let alice = s.user("alice");
    let bob = s.user("bob");
    assert_eq!(s.get(&alice, "repos").status, 200);
    let login = |resp: Resp| (resp.status, resp.location) == (303, Some("/".to_string()));
    // The cookie alone, as another server on localhost would get it.
    let other_path = Browser { base: "/s/0000".into(), ..alice.clone() };
    assert!(login(s.get(&other_path, "repos")));
    // The path alone, and the path with someone else's cookie.
    assert!(login(s.get(&Browser { cookies: String::new(), ..alice.clone() }, "repos")));
    assert!(login(s.get(&Browser { cookies: bob.cookies.clone(), ..alice.clone() }, "repos")));
    let csrf = s.csrf(&alice);
    let path = format!("{}/logout", alice.base);
    assert!(login(s.request("POST", &path, &bob.cookies, &[("_csrf", &csrf)])));
    assert_eq!(s.get(&alice, "repos").status, 200);
    // Sessions run out when idle, and at the latest after half a day.
    let db = &s.w.broker.db;
    db.conn().execute("UPDATE sessions SET last_seen = last_seen - 1801", []).unwrap();
    assert!(login(s.get(&alice, "repos")));
    let alice = s.login("alice", PASSWORD);
    db.conn().execute("UPDATE sessions SET created = created - 43201", []).unwrap();
    assert!(login(s.get(&alice, "repos")));
    // Logging out ends the session for good.
    let alice = s.login("alice", PASSWORD);
    let resp = s.post(&alice, "logout", &[]);
    assert!(resp.set_cookie.as_deref().unwrap().contains("Max-Age=0"));
    assert!(login(s.get(&alice, "repos")));
    // The database holds no session id or secret as such.
    let alice = s.login("alice", PASSWORD);
    let id = alice.cookies.split('=').nth(1).unwrap();
    let stored: i64 = db
        .conn()
        .query_row(
            "SELECT count(*) FROM sessions WHERE id_hash = ?1 OR secret_hash = ?2",
            [id, &alice.base[3..]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, 0);
}

#[test]
fn a_change_needs_our_origin_our_host_and_the_form_token() {
    let s = Site::new();
    let alice = s.user("alice");
    let csrf = s.csrf(&alice);
    let id = s.repo_id("alice", "o/a").to_string();
    let path = format!("{}/repos/{id}/delete", alice.base);
    let req = |origin: Option<&str>, host: &str, token: &str| Req {
        method: "POST".into(),
        path: path.clone(),
        host: host.into(),
        origin: origin.map(Into::into),
        cookies: alice.cookies.clone(),
        form: vec![("_csrf".to_string(), token.to_string())],
        ..Default::default()
    };
    let ours = format!("http://{HOST}");
    // Another port on localhost is another origin, and gets the cookie all the same.
    for (origin, host, token, status) in [
        (None, HOST, csrf.as_str(), 403),
        (Some("http://localhost:9999"), HOST, &csrf, 403),
        (Some("https://localhost:8443"), HOST, &csrf, 403),
        (Some("null"), HOST, &csrf, 403),
        (Some(ours.as_str()), "evil.example", &csrf, 400),
        (Some("http://evil.example"), "evil.example", &csrf, 400),
        (Some(&ours), HOST, "", 403),
        (Some(&ours), HOST, &"0".repeat(64), 403),
    ] {
        assert_eq!(s.web.handle(&req(origin, host, token)).status, status, "{origin:?} {host} {token}");
    }
    s.repo_id("alice", "o/a");
    for method in ["PUT", "DELETE", "HEAD"] {
        let mut other = req(Some(&ours), HOST, &csrf);
        other.method = method.into();
        assert_eq!(s.web.handle(&other).status, 405);
    }
    // And with everything in place it goes through.
    assert_eq!(s.web.handle(&req(Some(&ours), HOST, &csrf)).status, 303);
    assert!(s.w.broker.db.repo_rows(s.w.broker.db.user_id("alice").unwrap().unwrap()).unwrap().is_empty());
}

#[test]
fn repos_are_set_up_in_the_browser_and_tokens_never_come_back() {
    let s = Site::new();
    let alice = s.user("alice");
    let token = "github_pat_NEWTOKEN123";
    let form = |repo: &'static str, token: &'static str, prefix: &'static str| {
        vec![
            ("repo", repo),
            ("token", token),
            ("prefix", prefix),
            ("tool", "github_push"),
            ("tool", "made_up"),
        ]
    };
    // Nothing is stored for a token that cannot be one, or for rules that make no sense.
    assert!(
        s.done(&alice, "repos/add", &form("o/new", "not a token!", "al/"))
            .contains("does not look like a GitHub token")
    );
    assert!(s.done(&alice, "repos/add", &form("o/new/x", token, "al/")).contains("class=\"err\""));
    assert!(s.done(&alice, "repos/add", &form("o/new", token, "")).contains("class=\"err\""));
    s.w.api.on("GET /repos/o/new", json!({"full_name": "O/New", "default_branch": "main"}));
    assert!(
        s.done(&alice, "repos/add", &form("o/new", token, "ma"))
            .contains("would cover the default branch main")
    );
    assert_eq!(s.w.broker.db.repo_rows(s.w.broker.db.user_id("alice").unwrap().unwrap()).unwrap().len(), 1);

    // Added under the name GitHub gives it, with the tools that exist.
    let page = s.done(&alice, "repos/add", &form("o/new", token, "al/"));
    assert!(page.contains("Added O/New. The token can read it; its default branch is main."), "{page}");
    assert!(s.w.api.seen.lock().unwrap().last().unwrap().headers.contains("bearer github_pat_newtoken123"));
    let id = s.repo_id("alice", "O/New");
    let row = s.w.broker.db.repo_row(s.w.broker.db.user_id("alice").unwrap().unwrap(), id).unwrap();
    assert_eq!(
        (row.branch_prefix.as_str(), row.tools, row.enabled),
        ("al/", vec!["github_push".to_string()], true)
    );
    // The agent sees it at once.
    assert!(s.w.ok("github_repos", json!({})).contains("O/New: branch prefix al/"));
    assert!(s.done(&alice, "repos/add", &form("o/new", token, "al/")).contains("already configured"));

    // Changing the rules.
    let edit = format!("repos/{id}/edit");
    let page = s.done(&alice, &edit, &[("prefix", "alice/"), ("tool", "github_fetch"), ("enabled", "1")]);
    assert!(page.contains("Saved the rules for O/New."));
    assert!(
        s.w.ok("github_repos", json!({}))
            .contains("O/New: branch prefix alice/, default branch main, tools: github_fetch")
    );
    assert!(
        s.done(&alice, &edit, &[("prefix", "m"), ("enabled", "1")])
            .contains("would cover the default branch")
    );
    s.done(&alice, &edit, &[("prefix", "alice/")]);
    assert!(!s.w.ok("github_repos", json!({})).contains("O/New"), "switched off");

    // A new token is checked, and a bad one is refused without touching the old one.
    let replace = format!("repos/{id}/token");
    assert!(
        s.done(&alice, &replace, &[("token", "bad token")]).contains("does not look like a GitHub token")
    );
    s.w.api.on("GET /repos/O/New", json!({"full_name": "O/Renamed", "default_branch": "trunk"}));
    let page = s.done(&alice, &replace, &[("token", "ghp_SECOND456")]);
    assert!(page.contains("The token can read O/Renamed."), "{page}");
    assert!(page.contains("<code>trunk</code>"));

    // No page and no log gives a token back.
    let mut seen = s.audit();
    for page in ["repos", "accounts", "audit", "audit/all", "account", "users"] {
        seen.push_str(&s.get(&alice, page).body);
    }
    for secret in [token, "ghp_SECOND456", TOKEN, "bobToken"] {
        assert!(!seen.contains(secret), "{secret}");
    }

    // Deleting removes the entry, the token and the mirror.
    let mirror = s.w.dir.path().join(format!("data/mirrors/{id}.git"));
    std::fs::create_dir_all(&mirror).unwrap();
    assert!(s.done(&alice, &format!("repos/{id}/delete"), &[]).contains("Deleted the entry for O/Renamed"));
    assert!(!mirror.exists());
    let left: i64 =
        s.w.broker.db.conn().query_row("SELECT count(*) FROM credentials", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 2, "alice's first repo and bob's");
}

#[test]
fn a_token_that_cannot_read_the_repo_yet_is_kept_but_off() {
    let s = Site::new();
    let alice = s.user("alice");
    s.w.api.raw("GET /repos/org/wait", 404, "", "{\"message\":\"Not Found ECHO\"}");
    let form =
        [("repo", "org/wait"), ("token", "github_pat_WAITING"), ("prefix", "al/"), ("tool", "github_push")];
    let page = s.done(&alice, "repos/add", &form);
    assert!(page.contains("Saved org/wait, but switched off"), "{page}");
    assert!(page.contains("HTTP 404") && !page.to_lowercase().contains("github_pat_waiting"), "{page}");
    assert!(!s.w.ok("github_repos", json!({})).contains("org/wait"));
    let id = s.repo_id("alice", "org/wait");
    // It cannot be switched on by hand, only by a check that works.
    let page = s.done(&alice, &format!("repos/{id}/edit"), &[("prefix", "al/"), ("enabled", "1")]);
    assert!(page.contains("stays off until"));
    assert!(s.done(&alice, &format!("repos/{id}/check"), &[]).contains("could not read org/wait"));
    s.w.api.on("GET /repos/org/wait", json!({"full_name": "org/wait", "default_branch": "main"}));
    assert!(s.done(&alice, &format!("repos/{id}/check"), &[]).contains("The entry is now on."));
    assert!(s.w.ok("github_repos", json!({})).contains("org/wait"));
}

#[test]
fn sensitive_changes_ask_for_the_password_again() {
    let s = Site::new();
    let alice = s.user("alice");
    let id = s.repo_id("alice", "o/a");
    let edit = format!("repos/{id}/edit");
    let form = [("prefix", "new/"), ("tool", "github_push"), ("enabled", "1")];
    let prefix = || {
        s.w.broker.db.repo_row(s.w.broker.db.user_id("alice").unwrap().unwrap(), id).unwrap().branch_prefix
    };
    s.w.broker.db.conn().execute("UPDATE sessions SET last_password = last_password - 301", []).unwrap();
    // The change waits, and the page carries what was submitted.
    let ask = s.post(&alice, &edit, &form);
    assert_eq!(ask.status, 200);
    assert!(ask.body.contains("Confirm with your password"));
    assert!(
        ask.body.contains("name=\"prefix\" value=\"new/\"")
            && ask.body.contains("name=\"tool\" value=\"github_push\"")
    );
    assert_eq!(prefix(), "daniel/");
    let mut with = form.to_vec();
    with.push(("_password", "not the password"));
    let wrong = s.post(&alice, &edit, &with);
    assert!(wrong.status == 200 && wrong.body.contains("That was not the password."));
    assert_eq!(prefix(), "daniel/");
    std::thread::sleep(std::time::Duration::from_millis(1100));
    with.pop();
    with.push(("_password", PASSWORD));
    assert_eq!(s.post(&alice, &edit, &with).status, 303);
    assert_eq!(prefix(), "new/");
    // For a while after that, no question.
    assert_eq!(s.post(&alice, &edit, &[("prefix", "newer/"), ("enabled", "1")]).status, 303);
    assert_eq!(prefix(), "newer/");
    // Reading and getting a link code are not sensitive.
    s.w.broker.db.conn().execute("UPDATE sessions SET last_password = last_password - 301", []).unwrap();
    assert_eq!(s.get(&alice, "repos").status, 200);
    assert!(s.post(&alice, "accounts/code", &[]).body.contains("Link code:"));
    for action in
        ["repos/add", "accounts/5001/unlink", "accounts/5001/limits", "accounts/5001/confirm", "users/add"]
    {
        assert!(s.post(&alice, action, &[]).body.contains("Confirm with your password"), "{action}");
    }
    // A token that was typed is asked for again, not sent back in the page.
    let ask =
        s.post(&alice, "repos/add", &[("repo", "o/new"), ("token", "ghp_TYPED"), ("prefix", "al/")]).body;
    assert!(ask.contains("name=\"repo\" value=\"o/new\"") && ask.contains("The token, once more"));
    assert!(!ask.contains("ghp_TYPED"));
}

#[test]
fn the_password_is_changed_with_the_old_one() {
    let s = Site::new();
    let alice = s.user("alice");
    let elsewhere = s.login("alice", PASSWORD);
    let new = "a much better password";
    let change = |old: &str, new: &str, again: &str| {
        s.post(&alice, "account/password", &[("_password", old), ("new", new), ("again", again)])
    };
    assert!(change("not the password", new, new).body.contains("That was not the password."));
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let page =
        s.done(&alice, "account/password", &[("_password", PASSWORD), ("new", new), ("again", "other")]);
    assert!(page.contains("The two entries differ."));
    let page =
        s.done(&alice, "account/password", &[("_password", PASSWORD), ("new", "short"), ("again", "short")]);
    assert!(page.contains("at least 12 characters"));
    assert_eq!(change(PASSWORD, new, new).status, 303);
    // This session goes on, the other one is over, and only the new password logs in.
    assert_eq!(s.get(&alice, "account").status, 200);
    assert_eq!(s.get(&elsewhere, "account").status, 303);
    assert_eq!(s.request("POST", "/login", "", &[("username", "alice"), ("password", PASSWORD)]).status, 401);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    s.login("alice", new);
    assert!(!s.audit().contains(new));
}

#[test]
fn a_unix_account_is_linked_by_a_code_and_a_confirmation() {
    let s = Site::new();
    let alice = s.user("alice");
    let page = s.post(&alice, "accounts/code", &[]).body;
    let at = page.find("Link code: <code>").unwrap() + 17;
    let code = &page[at..at + 10];
    // The account presents the code over the agent socket.
    s.w.become_uid(STRANGER);
    let mut raw = Raw::connect(&s.w);
    raw.send("link", json!({"code": code}), None);
    assert!(s.w.err("github_repos", json!({})).contains("not linked"), "a claim alone links nothing");
    let page = s.get(&alice, "accounts").body;
    assert!(page.contains(&format!("<code>agent{STRANGER}</code> (uid {STRANGER}) wants to link")), "{page}");
    // Someone else cannot confirm it.
    let bob = s.user("bob");
    assert!(s.done(&bob, &format!("accounts/{STRANGER}/confirm"), &[]).contains("no unexpired claim"));
    assert!(s.done(&alice, &format!("accounts/{STRANGER}/confirm"), &[]).contains("Linked the unix account"));
    assert!(s.w.ok("github_repos", json!({})).contains("o/a"));

    // Limiting it to some repos; a repo of someone else in the form changes nothing.
    let theirs = s.repo_id("bob", "o/b").to_string();
    let limits = format!("accounts/{STRANGER}/limits");
    s.done(&alice, &limits, &[("repo", &theirs)]);
    assert!(s.w.err("github_pr_list", json!({})).contains("no repos are available"));
    let mine = s.repo_id("alice", "o/a").to_string();
    s.done(&alice, &limits, &[("repo", &mine), ("repo", &theirs)]);
    assert!(s.w.ok("github_repos", json!({})).starts_with("o/a:"));
    assert!(s.done(&bob, &limits, &[("all", "1")]).contains("no such linked account"));

    assert!(s.done(&bob, &format!("accounts/{STRANGER}/unlink"), &[]).contains("no such linked account"));
    assert!(s.done(&alice, &format!("accounts/{STRANGER}/unlink"), &[]).contains("Unlinked uid"));
    assert!(s.w.err("github_repos", json!({})).contains("not linked"));
}

#[test]
fn users_only_reach_what_is_theirs() {
    let s = Site::new();
    let alice = s.user("alice");
    let bob = s.user("bob");
    // Bob is no admin.
    for page in ["users", "audit/all"] {
        assert_eq!(s.get(&bob, page).status, 404);
    }
    for action in ["users/add", "users/1/delete", "users/1/reset", "users/2/admin"] {
        assert_eq!(s.post(&bob, action, &[("username", "eve")]).status, 404, "{action}");
    }
    // Nobody acts on another user's repo, admin or not.
    let (hers, his) = (s.repo_id("alice", "o/a"), s.repo_id("bob", "o/b"));
    for (who, id) in [(&alice, his), (&bob, hers)] {
        for action in ["edit", "token", "delete", "check"] {
            let form = [("prefix", "x/"), ("token", "ghp_X")];
            let page = s.done(who, &format!("repos/{id}/{action}"), &form);
            assert!(page.contains("no such repo entry"), "{action}: {page}");
        }
    }
    assert!(!s.get(&alice, "repos").body.contains("o/b") && !s.get(&bob, "repos").body.contains("o/a"));
    // Each sees their own audit entries; the admin can see all.
    s.w.ok("github_repos", json!({}));
    s.w.broker
        .db
        .conn()
        .execute("UPDATE audit SET detail = '<script>x</script>' WHERE event = 'start'", [])
        .unwrap();
    let own = s.get(&alice, "audit").body;
    assert!(
        own.contains("github_repos")
            && own.contains("&lt;script&gt;x&lt;/script&gt;")
            && !own.contains("<script>")
    );
    assert!(!s.get(&bob, "audit").body.contains("github_repos"));
    assert!(s.get(&alice, "audit/all").body.contains("bob"));
    assert!(!s.get(&alice, "audit?tool=github_push").body.contains("github_repos"));
    assert!(s.get(&alice, "audit?tool=github_repos").body.contains("alice (uid 5001)"));
}

#[test]
fn admins_manage_users_but_one_admin_always_remains() {
    let s = Site::new();
    let alice = s.user("alice");
    let db = &s.w.broker.db;
    assert!(s.done(&alice, "users/add", &[("username", "Bad Name")]).contains("A username starts with"));
    assert!(s.done(&alice, "users/add", &[("username", "bob")]).contains("There is a user bob already."));
    // A new user gets a link, sets a password and is in.
    let page = s.post(&alice, "users/add", &[("username", "carol")]).body;
    let at = page.find("http://localhost:8443/setup/").unwrap();
    let link = &page[at + 21..at + 28 + 52];
    assert_eq!(s.request("POST", link, "", &[("new", PASSWORD), ("again", PASSWORD)]).status, 303);
    let carol = s.login("carol", PASSWORD);
    assert_eq!(s.get(&carol, "users").status, 404);
    let id = |name: &str| db.user_id(name).unwrap().unwrap();
    // The only admin cannot be taken away, by herself or through anyone.
    let own = id("alice");
    for action in ["disable", "delete", "unadmin"] {
        assert!(
            s.done(&alice, &format!("users/{own}/{action}"), &[]).contains("cannot be done to your own user")
        );
    }
    s.done(&alice, &format!("users/{}/admin", id("carol")), &[]);
    let carol = s.login("carol", PASSWORD);
    assert_eq!(s.get(&carol, "users").status, 200);
    db.conn().execute("UPDATE users SET disabled = 1 WHERE username = 'carol'", []).unwrap();
    db.conn().execute("UPDATE users SET disabled = 0 WHERE username = 'carol'", []).unwrap();
    s.done(&carol, &format!("users/{own}/unadmin"), &[]);
    assert_eq!(s.get(&alice, "users").status, 404);
    let me = id("carol");
    assert!(s.done(&carol, &format!("users/{me}/unadmin"), &[]).contains("cannot be done to your own user"));
    db.conn().execute("UPDATE users SET is_admin = 1 WHERE username = 'alice'", []).unwrap();
    db.conn().execute("UPDATE users SET disabled = 1 WHERE username = 'carol'", []).unwrap();
    assert_eq!(s.get(&carol, "users").status, 303, "a disabled user's session is over");
    db.conn().execute("UPDATE users SET disabled = 0 WHERE username = 'carol'", []).unwrap();

    // Disabling stops the user's agents at once, and ends their sessions.
    s.set_password("bob", PASSWORD);
    let bob = s.login("bob", PASSWORD);
    s.w.become_uid(BOB);
    assert!(s.w.ok("github_repos", json!({})).contains("o/b"));
    assert!(s.done(&alice, &format!("users/{}/disable", id("bob")), &[]).contains("Disabled bob."));
    assert!(s.w.err("github_repos", json!({})).contains("not linked"));
    assert_eq!(s.get(&bob, "repos").status, 303);
    s.done(&alice, &format!("users/{}/enable", id("bob")), &[]);
    assert!(s.w.ok("github_repos", json!({})).contains("o/b"));
    // A reset link lets the admin hand the account back, without learning the password.
    let page = s.post(&alice, &format!("users/{}/reset", id("bob")), &[]).body;
    assert!(page.contains("One-time link for bob"));
    // Deleting takes the user's tokens, repos, links and mirrors along.
    let repo = s.repo_id("bob", "o/b");
    let mirror = s.w.dir.path().join(format!("data/mirrors/{repo}.git"));
    std::fs::create_dir_all(&mirror).unwrap();
    assert!(s.done(&alice, &format!("users/{}/delete", id("bob")), &[]).contains("Deleted bob"));
    assert!(s.w.err("github_repos", json!({})).contains("not linked"));
    assert!(!mirror.exists());
    let left: i64 = db
        .conn()
        .query_row(
            "SELECT (SELECT count(*) FROM credentials WHERE token = 'bobToken')
                  + (SELECT count(*) FROM linked_accounts WHERE uid = ?1)",
            [BOB],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(left, 0);
    let audit = s.audit();
    for event in ["user created", "user admin", "user disable", "user delete", "reset link made"] {
        assert!(audit.contains(&format!("\"event\":\"{event}\"")), "{event}");
    }
}

#[test]
fn over_the_socket_pages_come_with_strict_headers() {
    let s = Site::new();
    let path = s.w.dir.path().join("run/admin.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let web = s.web.clone();
    std::thread::spawn(move || serve(web, listener));
    let exchange = |request: &str| {
        let mut stream = UnixStream::connect(&path).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        reply
    };
    let reply = exchange("GET / HTTP/1.1\r\nHost: localhost:8443\r\nConnection: close\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    let lower = reply.to_lowercase();
    for header in [
        "cache-control: no-store",
        "referrer-policy: no-referrer",
        "x-content-type-options: nosniff",
        "content-security-policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        "content-type: text/html; charset=utf-8",
    ] {
        assert!(lower.contains(header), "{header}\n{reply}");
    }
    assert!(reply.contains("name=\"password\"") && !lower.contains("<script"));
    // A whole login, as bytes on the socket.
    s.set_password("alice", PASSWORD);
    let form = format!("username=alice&password={}", PASSWORD.replace(' ', "+"));
    let reply = exchange(&format!(
        "POST /login HTTP/1.1\r\nHost: localhost:8443\r\nOrigin: http://localhost:8443\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{form}",
        form.len()
    ));
    assert!(reply.starts_with("HTTP/1.1 303"), "{reply}");
    let lower = reply.to_lowercase();
    assert!(lower.contains("set-cookie: ab_session=") && lower.contains("location: /s/"), "{reply}");
    assert!(
        exchange("GET / HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
            .starts_with("HTTP/1.1 400")
    );
    let huge = "x".repeat(70_000);
    let reply = exchange(&format!(
        "POST /login HTTP/1.1\r\nHost: localhost:8443\r\nOrigin: http://localhost:8443\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{huge}",
        huge.len()
    ));
    assert!(reply.starts_with("HTTP/1.1 400"), "{}", &reply[..40]);
}

//! The web UI: who may do what is set here, by people who logged in.
//!
//! A request is trusted only as far as its session goes. Every page behind the login needs the
//! session cookie and the session's secret in the path; every change also needs the session's
//! form token and comes from the page's own origin.

pub mod auth;
mod http;
mod pages;
pub mod store;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::db::{AuditEntry, hash_secret, now, random_base32};
use crate::dispatch::{Broker, log};
use crate::error::{Error, Result, refuse};
use crate::github::{TOOLS, rules};
use crate::scrub::{head, scrub};
use auth::{Cost, Delays, check_new_password, hash_password, verify_password};
pub use http::{pairs, serve};
use pages::Frame;
use store::{Session, User};

const COOKIE: &str = "ab_session";
/// A sensitive change needs the password again after this many seconds.
const PASSWORD_FRESH: i64 = 5 * 60;
const AUDIT_ROWS: u32 = 200;
const FAILED_LOGINS_AUDITED_PER_MINUTE: u32 = 30;

/// A request, reduced to what the UI looks at.
#[derive(Default, Clone)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub host: String,
    pub origin: Option<String>,
    pub cookies: String,
    pub form: Vec<(String, String)>,
}

#[derive(Default)]
pub struct Resp {
    pub status: u16,
    pub location: Option<String>,
    pub set_cookie: Option<String>,
    pub body: String,
}

impl Resp {
    fn page(body: String) -> Resp {
        Resp { status: 200, body, ..Default::default() }
    }

    fn error(status: u16, text: &str) -> Resp {
        Resp { status, body: pages::plain("Not possible", text), ..Default::default() }
    }

    fn redirect(to: String) -> Resp {
        Resp { status: 303, location: Some(to), ..Default::default() }
    }
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

fn fields<'a>(fields: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    fields.iter().filter(|(n, _)| n == name).map(|(_, v)| v.as_str()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Web {
    broker: Arc<Broker>,
    cost: Cost,
    delays: Delays,
    audited_failures: Mutex<(Instant, u32)>,
    /// The hash of the link token for creating the first admin, while there is no user.
    first_run: Mutex<Option<Vec<u8>>>,
}

/// A request that came with a valid session.
struct Ctx<'a> {
    req: &'a Req,
    /// The cookie's value.
    id: &'a str,
    base: String,
    csrf: String,
    session: Session,
}

impl Ctx<'_> {
    fn user(&self) -> &User {
        &self.session.user
    }

    fn frame(&self) -> Frame<'_> {
        Frame {
            base: &self.base,
            csrf: &self.csrf,
            user: self.user(),
            ok: field(&self.req.query, "ok"),
            err: field(&self.req.query, "err"),
        }
    }

    fn back(&self, page: &str, kind: &str, text: &str) -> Resp {
        Resp::redirect(format!("{}/{page}?{kind}={}", self.base, http::encode(&head(text, 600))))
    }

    fn done(&self, page: &str, text: &str) -> Resp {
        self.back(page, "ok", text)
    }
}

impl Web {
    pub fn new(broker: Arc<Broker>, cost: Cost) -> Web {
        Web {
            broker,
            cost,
            delays: Delays::default(),
            audited_failures: Mutex::new((Instant::now(), 0)),
            first_run: Mutex::default(),
        }
    }

    /// While there is no user at all: a new link path where the first admin is created. Anyone
    /// on the machine can reach the web UI, so only who can read this may set it up. The link
    /// works once, and until this is called again.
    pub fn first_run_link(&self) -> Result<Option<String>> {
        if !self.broker.db.users()?.is_empty() {
            return Ok(None);
        }
        let token = random_base32(52);
        *self.first_run.lock().unwrap_or_else(|e| e.into_inner()) = Some(hash_secret(&token));
        Ok(Some(format!("/setup/{token}")))
    }

    /// Creates the first admin, if `token` is the one for it.
    fn first_admin(&self, req: &Req, token: &str) -> Result<Option<Resp>> {
        // Held to the end, so that two requests cannot both create one.
        let mut first_run = self.first_run.lock().unwrap_or_else(|e| e.into_inner());
        let fits = first_run.as_ref().is_some_and(|hash| auth::same(hash, &hash_secret(token)));
        if !fits {
            return Ok(None);
        }
        let db = &self.broker.db;
        if !db.users()?.is_empty() {
            *first_run = None;
            return Ok(None);
        }
        let name = field(&req.form, "username").unwrap_or_default().trim();
        if req.method != "POST" {
            return Ok(Some(Resp::page(pages::setup(token, None, None))));
        }
        let new = field(&req.form, "new").unwrap_or_default();
        let problem = match (check_username(name), field(&req.form, "again") == Some(new)) {
            (Err(e), _) => Some(e.public().to_string()),
            (Ok(()), false) => Some("the two entries differ".to_string()),
            (Ok(()), true) => check_new_password(new).err(),
        };
        if let Some(problem) = problem {
            return Ok(Some(Resp::page(pages::setup(token, None, Some((name, &problem))))));
        }
        let hash = hash_password(new, self.cost).ok_or_else(|| Error::Internal("hashing failed".into()))?;
        let id = db.add_user(name, true)?;
        db.set_password(id, &hash, None)?;
        *first_run = None;
        self.audit(Some(name), "first admin created", true, None, "");
        let done = "You are the first admin. Log in with the name and password you chose.";
        Ok(Some(Resp::redirect(format!("/?ok={}", http::encode(done)))))
    }

    /// Answers one request. Failures inside become a plain error page.
    pub fn handle(&self, req: &Req) -> Resp {
        match self.route(req) {
            Ok(resp) => resp,
            Err(Error::Refused(text)) => Resp::error(400, &text),
            Err(Error::Internal(text)) => {
                log(&format!("web: {text}"), None);
                Resp::error(500, "internal error; see the daemon's log")
            }
        }
    }

    fn route(&self, req: &Req) -> Result<Resp> {
        // Not reachable under another name, which would be another origin with other cookies.
        let host = req.host.rsplit_once(':').map_or(req.host.as_str(), |(h, port)| {
            if port.bytes().all(|b| b.is_ascii_digit()) { h } else { req.host.as_str() }
        });
        if !matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
            return Ok(Resp::error(400, "open this as localhost or 127.0.0.1"));
        }
        match req.method.as_str() {
            "GET" => {}
            // A change must come from one of our own pages.
            "POST" if req.origin.as_deref() == Some(&format!("http://{}", req.host)) => {}
            "POST" => return Ok(Resp::error(403, "this request did not come from the broker's own page")),
            _ => return Ok(Resp::error(405, "method not allowed")),
        }
        let post = req.method == "POST";
        let path = req.path.as_str();
        if let Some(rest) = path.strip_prefix("/s/") {
            let (secret, rest) = rest.split_once('/').unwrap_or((rest, ""));
            return self.behind_login(req, secret, rest);
        }
        match (post, path) {
            (false, "/") => Ok(Resp::page(pages::login(field(&req.query, "ok"), None))),
            (true, "/login") => self.login(req),
            (_, p) if p.starts_with("/setup/") => self.setup(req, &p["/setup/".len()..]),
            _ => Ok(Resp::error(404, "no such page")),
        }
    }

    fn audit(&self, user: Option<&str>, event: &str, ok: bool, resource: Option<&str>, detail: &str) {
        let written = self.broker.db.audit(&AuditEntry {
            event,
            username: user,
            resource,
            ok: Some(ok),
            detail: &head(&scrub(detail, None), 300),
            ..Default::default()
        });
        if let Err(e) = written {
            log(&format!("cannot audit {event}: {e}"), None);
        }
    }

    fn login(&self, req: &Req) -> Result<Resp> {
        let username = field(&req.form, "username").unwrap_or_default().trim();
        let password = field(&req.form, "password").unwrap_or_default();
        let fail =
            |text: &str| Ok(Resp { status: 401, body: pages::login(None, Some(text)), ..Default::default() });
        if let Some(wait) = self.delays.wait(username) {
            return fail(&format!("Too many attempts. Try again in {} seconds.", wait.as_secs() + 1));
        }
        let found = self.broker.db.login(username)?;
        let stored = found.as_ref().and_then(|(_, hash)| hash.as_deref());
        let right = verify_password(password, stored, self.cost);
        let user = found.as_ref().map(|(user, _)| user).filter(|user| right && !user.disabled);
        let Some(user) = user else {
            self.delays.failed(username);
            // Anyone on the machine can try to log in, so these must not fill the log.
            let audited = {
                let mut window = self.audited_failures.lock().unwrap_or_else(|e| e.into_inner());
                if window.0.elapsed().as_secs() >= 60 {
                    *window = (Instant::now(), 0);
                }
                window.1 += 1;
                window.1 <= FAILED_LOGINS_AUDITED_PER_MINUTE
            };
            if audited {
                self.audit(None, "login", false, None, &format!("as {}", head(username, 64)));
            }
            return fail("Wrong username or password.");
        };
        self.delays.succeeded(username);
        let (id, secret) = self.broker.db.create_session(user.id)?;
        self.audit(Some(&user.username), "login", true, None, "");
        let mut resp = Resp::redirect(format!("/s/{secret}/repos"));
        resp.set_cookie = Some(format!("{COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict"));
        Ok(resp)
    }

    /// Setting a password through a one-time link.
    fn setup(&self, req: &Req, token: &str) -> Result<Resp> {
        if let Some(resp) = self.first_admin(req, token)? {
            return Ok(resp);
        }
        let db = &self.broker.db;
        let Some(user) = db.one_time_link(token)? else {
            return Ok(Resp::error(404, "This link is used up or too old. Ask for a new one."));
        };
        if req.method != "POST" {
            return Ok(Resp::page(pages::setup(token, Some(&user.username), None)));
        }
        let new = field(&req.form, "new").unwrap_or_default();
        let problem = match field(&req.form, "again") == Some(new) {
            true => check_new_password(new).err(),
            false => Some("the two entries differ".to_string()),
        };
        if let Some(problem) = problem {
            return Ok(Resp::page(pages::setup(token, Some(&user.username), Some(("", &problem)))));
        }
        let hash = hash_password(new, self.cost).ok_or_else(|| Error::Internal("hashing failed".into()))?;
        if db.use_one_time_link(token, &hash)?.is_none() {
            return Ok(Resp::error(404, "This link is used up or too old. Ask for a new one."));
        }
        self.audit(Some(&user.username), "password set through a link", true, None, "");
        Ok(Resp::redirect(format!("/?ok={}", http::encode("Password set. Log in with it."))))
    }

    fn behind_login(&self, req: &Req, secret: &str, rest: &str) -> Result<Resp> {
        let id = req
            .cookies
            .split(';')
            .filter_map(|c| c.trim().split_once('='))
            .find(|(name, _)| *name == COOKIE)
            .map(|(_, value)| value);
        let session = match id {
            Some(id) => self.broker.db.session(id, secret)?,
            None => None,
        };
        // Whatever is wrong, the answer is the same: log in.
        let (Some(id), Some(session)) = (id, session) else {
            return Ok(Resp::redirect("/".into()));
        };
        let csrf = hex(&Sha256::digest(format!("form:{id}:{secret}")));
        let ctx = Ctx { req, id, base: format!("/s/{secret}"), csrf, session };
        if req.method == "POST" {
            let sent = field(&req.form, "_csrf").unwrap_or_default();
            if !auth::same(sent.as_bytes(), ctx.csrf.as_bytes()) {
                return Ok(Resp::error(
                    403,
                    "this form is not from your session; go back and reload the page",
                ));
            }
            return self.change(&ctx, rest);
        }
        self.show(&ctx, rest)
    }

    fn tools() -> Vec<&'static str> {
        TOOLS.iter().filter(|t| t.takes_repo()).map(|t| t.name).collect()
    }

    fn show(&self, ctx: &Ctx, rest: &str) -> Result<Resp> {
        let db = &self.broker.db;
        let (user, frame) = (ctx.user(), ctx.frame());
        let filter = |name: &str| field(&ctx.req.query, name).map(str::trim).filter(|v| !v.is_empty());
        let body = match rest {
            "" => return Ok(Resp::redirect(format!("{}/repos", ctx.base))),
            "repos" => frame.repos(&db.repo_rows(user.id)?, &Self::tools()),
            "accounts" => frame.accounts(
                &db.accounts(user.id)?,
                &db.pending_claims(user.id)?,
                &db.repo_rows(user.id)?,
                None,
            ),
            "audit" => {
                let rows = db.audit_page(Some(&user.username), filter("repo"), filter("tool"), AUDIT_ROWS)?;
                frame.audit(&rows, false, filter("repo").unwrap_or(""), filter("tool").unwrap_or(""))
            }
            "audit/all" if user.is_admin => {
                let rows = db.audit_page(None, filter("repo"), filter("tool"), AUDIT_ROWS)?;
                frame.audit(&rows, true, filter("repo").unwrap_or(""), filter("tool").unwrap_or(""))
            }
            "account" => frame.account(),
            "users" if user.is_admin => frame.users(&db.users()?, None),
            _ => return Ok(Resp::error(404, "no such page")),
        };
        Ok(Resp::page(body))
    }

    /// Asks for the password again unless it was entered a short while ago.
    fn fresh_password(&self, ctx: &Ctx, action: &str) -> Result<Option<Resp>> {
        let entered = field(&ctx.req.form, "_password");
        if entered.is_none() && now() - ctx.session.last_password <= PASSWORD_FRESH {
            return Ok(None);
        }
        let name = &ctx.user().username;
        let right = match entered {
            Some(_) if self.delays.wait(name).is_some() => false,
            Some(password) => {
                let stored = self.broker.db.password_hash(ctx.user().id)?;
                verify_password(password, stored.as_deref(), self.cost)
            }
            None => false,
        };
        if right {
            self.delays.succeeded(name);
            self.broker.db.password_entered(ctx.id)?;
            return Ok(None);
        }
        if entered.is_some() {
            self.delays.failed(name);
            self.audit(Some(name), "password check", false, None, action);
        }
        Ok(Some(Resp::page(ctx.frame().confirm(action, &ctx.req.form, entered.is_some()))))
    }

    fn change(&self, ctx: &Ctx, rest: &str) -> Result<Resp> {
        let parts: Vec<&str> = rest.split('/').collect();
        // A refusal goes back to the page it came from, where the form is.
        match self.changed(ctx, rest, &parts) {
            Err(Error::Refused(text)) => Ok(ctx.back(parts[0], "err", &text)),
            other => other,
        }
    }

    fn changed(&self, ctx: &Ctx, rest: &str, parts: &[&str]) -> Result<Resp> {
        if parts == ["logout"] {
            self.broker.db.end_session(ctx.id)?;
            let mut resp = Resp::redirect("/".into());
            resp.set_cookie = Some(format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"));
            return Ok(resp);
        }
        if parts == ["accounts", "code"] {
            let db = &self.broker.db;
            let user = ctx.user();
            let code = db.new_link_code(user.id)?;
            let (accounts, claims, repos) =
                (db.accounts(user.id)?, db.pending_claims(user.id)?, db.repo_rows(user.id)?);
            return Ok(Resp::page(ctx.frame().accounts(&accounts, &claims, &repos, Some(&code))));
        }
        if let ["repos", id, "check"] = parts[..] {
            return self.check_repo(ctx, id.parse().unwrap_or(0));
        }
        // Everything else changes who can do what.
        if let Some(ask) = self.fresh_password(ctx, rest)? {
            return Ok(ask);
        }
        match parts[..] {
            ["repos", "add"] => self.add_repo(ctx),
            ["repos", id, action] => self.change_repo(ctx, id.parse().unwrap_or(0), action),
            ["accounts", uid, action] => self.change_account(ctx, uid.parse().unwrap_or(0), action),
            ["account", "password"] => self.change_password(ctx),
            ["users", "add"] if ctx.user().is_admin => self.add_user(ctx),
            ["users", id, action] if ctx.user().is_admin => {
                self.change_user(ctx, id.parse().unwrap_or(0), action)
            }
            _ => Ok(Resp::error(404, "no such action")),
        }
    }

    /// The token as it may be stored, or why not.
    fn token<'a>(ctx: &'a Ctx) -> Result<&'a str> {
        static SHAPE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new("^[A-Za-z0-9_]+$").expect("valid pattern"));
        let token = field(&ctx.req.form, "token").unwrap_or_default().trim();
        if !SHAPE.is_match(token) {
            return refuse("That does not look like a GitHub token. Nothing was stored.");
        }
        Ok(token)
    }

    fn rules_from_form<'a>(ctx: &'a Ctx) -> Result<(&'a str, Vec<&'a str>)> {
        let prefix = field(&ctx.req.form, "prefix").unwrap_or_default().trim();
        rules::check_branch(&format!("{prefix}x"), prefix)?;
        let known = Self::tools();
        let tools: Vec<&str> =
            fields(&ctx.req.form, "tool").into_iter().filter(|t| known.contains(t)).collect();
        Ok((prefix, tools))
    }

    fn covers(prefix: &str, default_branch: &str) -> Result<()> {
        if !default_branch.is_empty() && default_branch.starts_with(prefix) {
            return refuse(format!("The prefix {prefix} would cover the default branch {default_branch}."));
        }
        Ok(())
    }

    fn add_repo(&self, ctx: &Ctx) -> Result<Resp> {
        let db = &self.broker.db;
        let user = ctx.user();
        let name = field(&ctx.req.form, "repo").unwrap_or_default().trim();
        rules::check_repo_name(name)?;
        let (prefix, tools) = Self::rules_from_form(ctx)?;
        let token = Self::token(ctx)?;
        let (text, id) = match self.broker.github.look_up_repo(name, token) {
            Ok((full_name, default_branch)) => {
                Self::covers(prefix, &default_branch)?;
                let id = db.add_github_repo(user.id, token, &full_name, prefix, &default_branch, &tools)?;
                db.set_repo_verified(user.id, id, &full_name, &default_branch)?;
                (
                    format!(
                        "Added {full_name}. The token can read it; its default branch is {default_branch}."
                    ),
                    id,
                )
            }
            // The token may be waiting for an organisation's approval, so keep it.
            Err(e) => {
                let id = db.add_github_repo(user.id, token, name, prefix, "", &tools)?;
                db.set_repo_enabled(user.id, id, false)?;
                let why = scrub(e.public(), Some(token));
                (
                    format!(
                        "Saved {name}, but switched off: the token could not read the repo.\n{why}\nUse \"Check the token\" once that is sorted out."
                    ),
                    id,
                )
            }
        };
        self.audit(
            Some(&user.username),
            "repo added",
            true,
            Some(name),
            &format!("entry {id}, prefix {prefix}"),
        );
        Ok(ctx.done("repos", &text))
    }

    /// Asks GitHub about the repo with the stored token, and switches a new entry on.
    fn check_repo(&self, ctx: &Ctx, id: i64) -> Result<Resp> {
        let db = &self.broker.db;
        let user = ctx.user();
        let row = db.repo_row(user.id, id)?;
        let token = db.repo_token(user.id, id)?;
        match self.broker.github.look_up_repo(&row.full_name, &token) {
            Ok((full_name, default_branch)) => {
                if let Err(e) = Self::covers(&row.branch_prefix, &default_branch) {
                    return Ok(ctx.back("repos", "err", e.public()));
                }
                db.set_repo_verified(user.id, id, &full_name, &default_branch)?;
                // An entry that was never usable is switched on by its first good check.
                let first = row.default_branch.is_empty();
                if first {
                    db.set_repo_enabled(user.id, id, true)?;
                }
                let on = if first { " The entry is now on." } else { "" };
                Ok(ctx.done("repos", &format!("The token can read {full_name}.{on}")))
            }
            Err(e) => {
                let why = scrub(e.public(), Some(&token));
                Ok(ctx.back("repos", "err", &format!("The token could not read {}.\n{why}", row.full_name)))
            }
        }
    }

    fn change_repo(&self, ctx: &Ctx, id: i64, action: &str) -> Result<Resp> {
        let db = &self.broker.db;
        let user = ctx.user();
        let row = db.repo_row(user.id, id)?;
        let name = row.full_name.as_str();
        let text = match action {
            "edit" => {
                let (prefix, tools) = Self::rules_from_form(ctx)?;
                Self::covers(prefix, &row.default_branch)?;
                let enabled = field(&ctx.req.form, "enabled").is_some();
                if enabled && row.default_branch.is_empty() {
                    return refuse("This entry stays off until \"Check the token\" succeeds.");
                }
                db.update_repo(user.id, id, prefix, &tools, enabled)?;
                let detail = format!("prefix {prefix}, enabled {enabled}, tools {}", tools.join(" "));
                self.audit(Some(&user.username), "repo rules changed", true, Some(name), &detail);
                format!("Saved the rules for {name}.")
            }
            "token" => {
                db.set_repo_token(user.id, id, Self::token(ctx)?)?;
                self.audit(Some(&user.username), "token replaced", true, Some(name), "");
                return self.check_repo(ctx, id);
            }
            "delete" => {
                db.delete_repo(user.id, id)?;
                self.broker.github.forget(id);
                self.audit(Some(&user.username), "repo deleted", true, Some(name), "");
                format!("Deleted the entry for {name}, with its token.")
            }
            _ => return Ok(Resp::error(404, "no such action")),
        };
        Ok(ctx.done("repos", &text))
    }

    fn change_account(&self, ctx: &Ctx, uid: u32, action: &str) -> Result<Resp> {
        let db = &self.broker.db;
        let user = ctx.user();
        let detail = format!("uid {uid}");
        let text = match action {
            "confirm" => {
                db.confirm_link(user.id, uid)?;
                self.audit(Some(&user.username), "link confirmed", true, None, &detail);
                format!("Linked the unix account with uid {uid}.")
            }
            "unlink" => {
                db.unlink(user.id, uid)?;
                self.audit(Some(&user.username), "account unlinked", true, None, &detail);
                format!("Unlinked uid {uid}.")
            }
            "limits" => {
                let all = field(&ctx.req.form, "all").is_some();
                let repos: Vec<i64> =
                    fields(&ctx.req.form, "repo").iter().filter_map(|r| r.parse().ok()).collect();
                db.set_account_limits(user.id, uid, all, &repos)?;
                let detail = format!("uid {uid}: all repos {all}, entries {repos:?}");
                self.audit(Some(&user.username), "account limits changed", true, None, &detail);
                format!("Saved which repos uid {uid} may use.")
            }
            _ => return Ok(Resp::error(404, "no such action")),
        };
        Ok(ctx.done("accounts", &text))
    }

    fn change_password(&self, ctx: &Ctx) -> Result<Resp> {
        // The form always carries the current password, so `fresh_password` has checked it.
        if field(&ctx.req.form, "_password").is_none() {
            return refuse("Enter your current password.");
        }
        let new = field(&ctx.req.form, "new").unwrap_or_default();
        if field(&ctx.req.form, "again") != Some(new) {
            return refuse("The two entries differ.");
        }
        check_new_password(new).or_else(refuse)?;
        let hash = hash_password(new, self.cost).ok_or_else(|| Error::Internal("hashing failed".into()))?;
        self.broker.db.set_password(ctx.user().id, &hash, Some(ctx.id))?;
        self.audit(Some(&ctx.user().username), "password changed", true, None, "");
        Ok(ctx.done("account", "Password changed."))
    }

    fn link_url(&self, ctx: &Ctx, token: &str) -> String {
        format!("http://{}/setup/{token}", ctx.req.host)
    }

    fn add_user(&self, ctx: &Ctx) -> Result<Resp> {
        let db = &self.broker.db;
        let name = field(&ctx.req.form, "username").unwrap_or_default().trim();
        check_username(name)?;
        if db.user_id(name)?.is_some() {
            return refuse(format!("There is a user {name} already."));
        }
        let id = db.add_user(name, false)?;
        let token = db.new_one_time_link(id, "setup")?;
        self.audit(Some(&ctx.user().username), "user created", true, None, name);
        let url = self.link_url(ctx, &token);
        Ok(Resp::page(ctx.frame().users(&db.users()?, Some((name, &url)))))
    }

    fn change_user(&self, ctx: &Ctx, id: i64, action: &str) -> Result<Resp> {
        let db = &self.broker.db;
        let Some(target) = db.user(id)? else { return refuse("no such user") };
        let name = target.username.as_str();
        let admin = &ctx.user().username;
        if action == "reset" {
            let token = db.new_one_time_link(id, "reset")?;
            self.audit(Some(admin), "reset link made", true, None, name);
            let url = self.link_url(ctx, &token);
            return Ok(Resp::page(ctx.frame().users(&db.users()?, Some((name, &url)))));
        }
        if id == ctx.user().id {
            return refuse("That cannot be done to your own user.");
        }
        // Someone must remain who can manage users.
        let takes_an_admin =
            matches!(action, "disable" | "delete" | "unadmin") && target.is_admin && !target.disabled;
        if takes_an_admin && db.active_admins()? <= 1 {
            return refuse("That would leave no admin.");
        }
        let text = match action {
            "disable" => {
                db.set_user_disabled(id, true)?;
                format!("Disabled {name}. Their linked accounts stop working at once.")
            }
            "enable" => {
                db.set_user_disabled(id, false)?;
                format!("Enabled {name}.")
            }
            "admin" => {
                db.set_user_admin(id, true)?;
                format!("{name} is now an admin.")
            }
            "unadmin" => {
                db.set_user_admin(id, false)?;
                format!("{name} is no longer an admin.")
            }
            "delete" => {
                let mirrors = db.resource_ids(id)?;
                db.delete_user(id)?;
                for mirror in mirrors {
                    self.broker.github.forget(mirror);
                }
                format!("Deleted {name}, with their tokens, repo entries and linked accounts.")
            }
            _ => return Ok(Resp::error(404, "no such action")),
        };
        self.audit(Some(admin), &format!("user {action}"), true, None, name);
        Ok(ctx.done("users", &text))
    }
}

/// Usernames are shown in pages, logs and links, so they stay plain.
pub fn check_username(name: &str) -> Result<()> {
    static SHAPE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new("^[a-z][a-z0-9_.-]{0,31}$").expect("valid pattern"));
    if !SHAPE.is_match(name) {
        return refuse(
            "A username starts with a lower-case letter and has up to 32 lower-case letters, digits, '.', '_' or '-'.",
        );
    }
    Ok(())
}

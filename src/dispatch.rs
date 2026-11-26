//! Decides about and runs operations. Every rule is enforced from here.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::db::{AuditEntry, Caller, Db, RepoEntry, random_base32};
use crate::error::{Error, Result, refuse};
use crate::github::{self, Begun, GitHub, Output, PendingPush};
use crate::platform::Identity;
use crate::scrub::{head, scrub, truncate_output};
use crate::spec::{self, Args, Flow, Tool, str_arg};

const UNLINKED: &str =
    "this unix account is not linked to a user; ask the human to link it in the agent-broker web UI";
/// How long an upload may take to start after its first step.
const PENDING_LIFETIME: Duration = Duration::from_secs(600);
const REFUSALS_PER_MINUTE: u32 = 60;
const CLAIMS_PER_MINUTE: u32 = 5;

pub struct Broker {
    pub db: Db,
    pub github: GitHub,
    pub identity: Box<dyn Identity>,
    own_uid: u32,
    refusals: Limiter,
    claims: Limiter,
}

/// Counts per uid in fixed one-minute windows.
struct Limiter {
    max: u32,
    windows: Mutex<HashMap<u32, (Instant, u32)>>,
}

impl Limiter {
    fn new(max: u32) -> Self {
        Limiter { max, windows: Mutex::default() }
    }

    fn allow(&self, uid: u32) -> bool {
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let w = windows.entry(uid).or_insert((now, 0));
        if now.duration_since(w.0) >= Duration::from_secs(60) {
            *w = (now, 0);
        }
        w.1 = w.1.saturating_add(1);
        w.1 <= self.max
    }
}

/// A call that passed every check.
struct Authorized {
    caller: Caller,
    tool: &'static Tool,
    repos: Vec<RepoEntry>,
    entry: Option<RepoEntry>,
}

impl Authorized {
    fn token(&self) -> Option<&str> {
        self.entry.as_ref().map(|e| e.token.as_str())
    }

    fn entry(&self) -> Result<&RepoEntry> {
        self.entry.as_ref().ok_or_else(|| Error::Internal("tool without a repo".into()))
    }
}

/// An upload between its two steps.
pub struct Pending {
    pub call_id: String,
    started: Instant,
    tool: String,
    args: Args,
    resource_id: i64,
    username: String,
    push: PendingPush,
}

impl Pending {
    /// Whether the second step comes too late.
    pub fn expired(&self) -> bool {
        self.started.elapsed() > PENDING_LIFETIME
    }

    /// How long the second step may still take to start.
    pub fn remaining(&self) -> Duration {
        PENDING_LIFETIME.saturating_sub(self.started.elapsed())
    }
}

/// What an operation sends back.
pub struct Reply {
    pub value: Value,
    pub blob: Option<tempfile::NamedTempFile>,
}

impl Reply {
    fn new(value: Value) -> Self {
        Reply { value, blob: None }
    }
}

impl Broker {
    pub fn new(db: Db, github: GitHub, identity: Box<dyn Identity>, own_uid: u32) -> Self {
        Broker {
            db,
            github,
            identity,
            own_uid,
            refusals: Limiter::new(REFUSALS_PER_MINUTE),
            claims: Limiter::new(CLAIMS_PER_MINUTE),
        }
    }

    pub fn caller(&self, uid: u32) -> Result<Option<Caller>> {
        self.db.caller(uid, self.identity.account_name(uid).as_deref())
    }

    fn linked(&self, uid: u32) -> Result<Caller> {
        match self.caller(uid)? {
            Some(caller) => Ok(caller),
            None => refuse(UNLINKED),
        }
    }

    /// The single place that decides whether a tool call is allowed.
    fn authorize(&self, uid: u32, tool: &str, args: &Args) -> Result<Authorized> {
        let caller = self.linked(uid)?;
        let Some(tool) = spec::find(tool) else { return refuse("unknown tool") };
        tool.validate(args)?;
        let repos = self.db.repos(&caller)?;
        let entry = if tool.takes_repo() {
            let entry = pick_repo(&repos, str_arg(args, "repo"))?.clone();
            if !entry.enabled_tools.iter().any(|t| t == tool.name) {
                return refuse(format!("{} is not enabled for {}", tool.name, entry.full_name));
            }
            github::check_args(tool.name, args, &entry)?;
            Some(entry)
        } else {
            None
        };
        Ok(Authorized { caller, tool, repos, entry })
    }

    /// Authorizes a call and writes its first audit entry. `upload` says whether the caller
    /// uses the two-step form.
    fn start(&self, uid: u32, call_id: &str, tool: &str, args: &Args, upload: bool) -> Result<Authorized> {
        let authorized =
            self.authorize(uid, tool, args).and_then(|auth| match (auth.tool.flow == Flow::Upload, upload) {
                (true, false) => refuse(format!("{} needs two steps", auth.tool.name)),
                (false, true) => refuse(format!("{} needs only one step", auth.tool.name)),
                _ => Ok(auth),
            });
        match authorized {
            Ok(auth) => {
                self.db.audit(&AuditEntry {
                    event: "start",
                    call_id: Some(call_id),
                    uid: Some(uid),
                    username: Some(&auth.caller.username),
                    resource: auth.entry.as_ref().map(|e| e.full_name.as_str()),
                    tool: Some(auth.tool.name),
                    ok: None,
                    detail: &audit_args(args, auth.token()),
                })?;
                Ok(auth)
            }
            Err(e) => Err(self.refused(uid, call_id, tool, e)),
        }
    }

    /// Scrubs and audits the refusal of a call that never started.
    fn refused(&self, uid: u32, call_id: &str, tool: &str, e: Error) -> Error {
        let e = self.scrub_refusal(uid, e);
        self.audit_refusal(uid, call_id, tool, &e);
        e
    }

    /// A refusal may quote the caller's input, which may contain a token it got elsewhere.
    fn scrub_refusal(&self, uid: u32, e: Error) -> Error {
        let Error::Refused(mut text) = e else { return e };
        let repos = match self.caller(uid) {
            Ok(Some(caller)) => self.db.repos(&caller).unwrap_or_default(),
            _ => vec![],
        };
        for repo in &repos {
            text = scrub(&text, Some(&repo.token));
        }
        Error::Refused(truncate_output(&scrub(&text, None)))
    }

    fn audit_refusal(&self, uid: u32, call_id: &str, tool: &str, e: &Error) {
        if !self.refusals.allow(uid) {
            return;
        }
        let username = self.caller(uid).ok().flatten().map(|c| c.username);
        let written = self.db.audit(&AuditEntry {
            event: "refused",
            call_id: Some(call_id),
            uid: Some(uid),
            username: username.as_deref(),
            tool: Some(&head(&scrub(tool, None), 100)),
            ok: Some(false),
            detail: &head(&scrub(e.public(), None), 300),
            ..Default::default()
        });
        if let Err(e) = written {
            log(&format!("cannot audit a refusal: {e}"), None);
        }
    }

    /// Writes the last audit entry. Failing to must not change the tool's result.
    fn audit_end(&self, uid: u32, call_id: &str, auth: &Authorized, ok: bool, text: &str) {
        let written = self.db.audit(&AuditEntry {
            event: "end",
            call_id: Some(call_id),
            uid: Some(uid),
            username: Some(&auth.caller.username),
            resource: auth.entry.as_ref().map(|e| e.full_name.as_str()),
            tool: Some(auth.tool.name),
            ok: Some(ok),
            detail: &head(text, 300),
        });
        if let Err(e) = written {
            log(&format!("cannot audit the end of {call_id}: {e}"), None);
        }
    }

    /// Scrubs and audits a tool's result. Nothing a tool produced bypasses this.
    fn end(
        &self,
        uid: u32,
        call_id: &str,
        auth: &Authorized,
        result: Result<Output>,
        note: &str,
    ) -> Result<Output> {
        let clean = |s: &str| truncate_output(&scrub(s, auth.token()));
        match result {
            Ok(mut out) => {
                out.text = clean(&out.text);
                self.audit_end(uid, call_id, auth, true, &format!("{note}{}", out.text));
                Ok(out)
            }
            Err(e) => {
                let e = match e {
                    Error::Refused(m) => Error::Refused(clean(&m)),
                    Error::Internal(m) => {
                        log(&format!("{call_id} {}: {m}", auth.tool.name), auth.token());
                        Error::Internal(clean(&m))
                    }
                };
                self.audit_end(uid, call_id, auth, false, e.public());
                Err(e)
            }
        }
    }

    pub fn whoami(&self, uid: u32) -> Result<Reply> {
        Ok(Reply::new(match self.caller(uid)? {
            None => json!({"linked": false}),
            Some(c) => {
                let repos: Vec<String> = self.db.repos(&c)?.into_iter().map(|r| r.full_name).collect();
                json!({"linked": true, "user": c.username, "repos": repos})
            }
        }))
    }

    pub fn link(&self, uid: u32, args: &Args) -> Result<Reply> {
        if uid == 0 || uid == self.own_uid {
            return refuse("this account cannot be linked");
        }
        let Some(name) = self.identity.account_name(uid) else {
            return refuse("this uid has no account name");
        };
        if !self.claims.allow(uid) {
            return refuse("too many attempts; wait a minute");
        }
        let result = self.db.claim_link_code(str_arg(args, "code").unwrap_or_default(), uid, &name);
        let detail = match &result {
            Ok(()) => format!("unix account {name}"),
            Err(e) => format!("unix account {name}: {}", e.public()),
        };
        self.db.audit(&AuditEntry {
            event: "link claim",
            uid: Some(uid),
            ok: Some(result.is_ok()),
            detail: &detail,
            ..Default::default()
        })?;
        result?;
        Ok(Reply::new(json!({
            "text": format!("claimed; now confirm {name} (uid {uid}) in the web UI")
        })))
    }

    pub fn tools_list(&self, uid: u32) -> Result<Reply> {
        self.linked(uid)?;
        let tools: Vec<Value> = spec::tools().iter().map(Tool::json).collect();
        Ok(Reply::new(json!({"tools": tools})))
    }

    /// Runs a one-step tool.
    pub fn call(&self, uid: u32, request: &Args) -> Result<Reply> {
        let call_id = random_base32(26);
        let (tool, args, local) = call_parts(request).map_err(|e| self.refused(uid, &call_id, "", e))?;
        let auth = self.start(uid, &call_id, tool, args, false)?;
        let result = match &auth.entry {
            None => Ok(Output::from(github::list_repos(&auth.repos))),
            Some(entry) => {
                self.db.max_blob().and_then(|max| self.github.run(auth.tool.name, args, local, entry, max))
            }
        };
        let out = self.end(uid, &call_id, &auth, result, "")?;
        Ok(Reply { value: json!({"text": out.text, "local": out.local}), blob: out.blob })
    }

    /// First step of an upload. Returns the pending call unless it is already finished.
    pub fn begin(&self, uid: u32, request: &Args) -> Result<(Reply, Option<Pending>)> {
        let call_id = random_base32(26);
        let (tool, args, local) = call_parts(request).map_err(|e| self.refused(uid, &call_id, "", e))?;
        let auth = self.start(uid, &call_id, tool, args, true)?;
        let begun = auth.entry().and_then(|entry| self.github.push_begin(entry, args, local));
        match begun {
            Ok(Begun::Pending(push)) => {
                let value = json!({
                    "call_id": call_id, "basis": push.basis, "need_blob": push.need_bundle,
                });
                let pending = Pending {
                    call_id,
                    started: Instant::now(),
                    tool: auth.tool.name.into(),
                    args: args.clone(),
                    resource_id: auth.entry()?.resource_id,
                    username: auth.caller.username.clone(),
                    push,
                };
                Ok((Reply::new(value), Some(pending)))
            }
            Ok(Begun::Done { text, tip }) => {
                let out = self.end(uid, &call_id, &auth, Ok(Output::from(text)), "")?;
                Ok((Reply::new(json!({"text": out.text, "local": {"tip": tip}})), None))
            }
            Err(e) => Err(self
                .end(uid, &call_id, &auth, Err(e), "")
                .err()
                .unwrap_or(Error::Internal("unreachable".into()))),
        }
    }

    /// Second step of an upload.
    pub fn finish(&self, uid: u32, pending: Pending, blob: Option<&Path>) -> Result<Reply> {
        let call_id = pending.call_id.as_str();
        // The rules may have changed since the first step.
        let auth = match self.authorize(uid, &pending.tool, &pending.args) {
            Ok(auth) if auth.entry.as_ref().is_some_and(|e| e.resource_id == pending.resource_id) => auth,
            Ok(_) => {
                self.abandon(uid, &pending, "the repo changed meanwhile");
                return refuse("the repo changed meanwhile; try again");
            }
            Err(e) => {
                let e = self.scrub_refusal(uid, e);
                self.abandon(uid, &pending, e.public());
                return Err(e);
            }
        };
        let mut forced = String::new();
        let mut tip = String::new();
        let result = if pending.expired() {
            refuse("the upload took too long to start; try again")
        } else {
            auth.entry()
                .and_then(|entry| self.github.push_finish(&self.db, entry, call_id, &pending.push, blob))
                .map(|pushed| {
                    if let Some((old, new)) = pushed.forced {
                        // First, so that cutting the entry never loses the ids.
                        forced = format!("forced, full ids: {old} -> {new}; ");
                    }
                    tip = pushed.tip;
                    Output::from(pushed.text)
                })
        };
        let out = self.end(uid, call_id, &auth, result, &forced)?;
        Ok(Reply::new(json!({"text": out.text, "local": {"tip": tip}})))
    }

    /// Audits that an upload will not be finished.
    pub fn abandon(&self, uid: u32, pending: &Pending, why: &str) {
        let written = self.db.audit(&AuditEntry {
            event: "end",
            call_id: Some(&pending.call_id),
            uid: Some(uid),
            username: Some(&pending.username),
            tool: Some(&pending.tool),
            ok: Some(false),
            detail: &head(&scrub(why, None), 300),
            ..Default::default()
        });
        if let Err(e) = written {
            log(&format!("cannot audit the end of {}: {e}", pending.call_id), None);
        }
    }
}

/// Writes to the daemon's log.
pub fn log(message: &str, token: Option<&str>) {
    eprintln!("agent-broker: {}", scrub(message, token));
}

fn pick_repo<'a>(repos: &'a [RepoEntry], name: Option<&str>) -> Result<&'a RepoEntry> {
    match (name, repos) {
        // The same answer whether the repo is someone else's or does not exist.
        (Some(name), _) => match repos.iter().find(|r| r.full_name.eq_ignore_ascii_case(name)) {
            Some(entry) => Ok(entry),
            None => {
                refuse(format!("repo {} is not available to this account; see github_repos", head(name, 100)))
            }
        },
        (None, [entry]) => Ok(entry),
        (None, []) => refuse("no repos are available to this account"),
        (None, _) => refuse("several repos are available; give the repo argument (see github_repos)"),
    }
}

fn call_parts(request: &Args) -> Result<(&str, &Args, &Args)> {
    static EMPTY: std::sync::LazyLock<Args> = std::sync::LazyLock::new(Map::new);
    let object = |name| match request.get(name) {
        None => Some(&*EMPTY),
        Some(v) => v.as_object(),
    };
    match (str_arg(request, "name"), object("arguments"), object("local")) {
        (Some(tool), Some(args), Some(local)) => Ok((tool, args, local)),
        _ => refuse("unknown tool"),
    }
}

/// Arguments for the audit log: scrubbed, each string cut to 200 characters.
fn audit_args(args: &Args, token: Option<&str>) -> String {
    let cut: Args = args
        .iter()
        .map(|(k, v)| {
            let v = match v {
                Value::String(s) => Value::String(head(&scrub(s, token), 200)),
                other => other.clone(),
            };
            (k.clone(), v)
        })
        .collect();
    Value::Object(cut).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_arguments_are_scrubbed_before_cutting() {
        let args = json!({"body": format!("{}secret-token", "x".repeat(195)), "n": 1});
        let out = audit_args(args.as_object().unwrap(), Some("secret-token"));
        assert!(!out.contains("secr"));
        assert!(out.contains("\"n\":1"));
    }

    #[test]
    fn limiter() {
        let l = Limiter::new(2);
        assert!(l.allow(1) && l.allow(1) && !l.allow(1) && l.allow(2));
    }

    #[test]
    fn repo_defaulting() {
        let entry = |n: &str| RepoEntry {
            resource_id: 1,
            full_name: n.into(),
            branch_prefix: "p/".into(),
            default_branch: "main".into(),
            enabled_tools: vec![],
            token: String::new(),
        };
        let two = [entry("o/a"), entry("o/b")];
        assert!(pick_repo(&two[..0], None).is_err());
        assert!(pick_repo(&two[..1], None).is_ok());
        assert!(pick_repo(&two, None).is_err());
        assert_eq!(pick_repo(&two, Some("O/B")).ok().unwrap().full_name, "o/b");
        assert!(pick_repo(&two, Some("o/c")).is_err());
    }
}

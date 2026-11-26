//! The HTML of the web UI. No scripts and nothing loaded from elsewhere.

use super::store::{Account, AuditRow, RepoRow, User};

/// Text as HTML text or as an attribute value.
pub fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = "
body { font: 15px/1.45 system-ui, sans-serif; margin: 0; color: #1c1c1c; background: #f6f6f4; }
header { background: #23272e; color: #fff; padding: .6rem 1.2rem; display: flex; gap: 1.2rem; align-items: baseline; flex-wrap: wrap; }
header a { color: #cfd8e3; text-decoration: none; } header a.here { color: #fff; font-weight: 600; }
header b { margin-right: .6rem; } header form { margin-left: auto; }
main { max-width: 60rem; margin: 1.2rem auto; padding: 0 1.2rem; }
section { background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: 1rem 1.2rem; margin-bottom: 1rem; }
h1 { font-size: 1.3rem; } h2 { font-size: 1.05rem; margin: 0 0 .6rem; }
table { border-collapse: collapse; width: 100%; } th, td { text-align: left; padding: .3rem .6rem .3rem 0; vertical-align: top; border-bottom: 1px solid #eee; }
label { display: block; margin: .5rem 0 .15rem; font-weight: 600; }
input[type=text], input[type=password] { width: 100%; max-width: 26rem; padding: .35rem; box-sizing: border-box; }
label.check { display: inline-block; font-weight: 400; margin: .1rem 1rem .1rem 0; }
button { padding: .35rem .8rem; margin-top: .6rem; } button.danger { color: #a40000; }
form.inline { display: inline; } form.inline button { margin: 0 .3rem 0 0; }
.ok, .err, .note { padding: .5rem .8rem; border-radius: 4px; margin-bottom: 1rem; white-space: pre-wrap; overflow-wrap: anywhere; }
.ok { background: #e3f4e1; } .err { background: #fbe3e1; } .note { background: #fff6d6; }
code { background: #eee; padding: .1rem .3rem; border-radius: 3px; overflow-wrap: anywhere; }
.muted { color: #666; } td.detail { overflow-wrap: anywhere; font-size: .9em; }
";

/// What every page behind the login needs.
pub struct Frame<'a> {
    /// `/s/<secret>`
    pub base: &'a str,
    pub csrf: &'a str,
    pub user: &'a User,
    pub ok: Option<&'a str>,
    pub err: Option<&'a str>,
}

fn document(title: &str, header: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{} - agent-broker</title><style>{STYLE}</style></head>\
         <body>{header}<main>{body}</main></body></html>",
        esc(title)
    )
}

fn notices(ok: Option<&str>, err: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(text) = ok.filter(|t| !t.is_empty()) {
        out.push_str(&format!("<div class=\"ok\">{}</div>", esc(text)));
    }
    if let Some(text) = err.filter(|t| !t.is_empty()) {
        out.push_str(&format!("<div class=\"err\">{}</div>", esc(text)));
    }
    out
}

impl Frame<'_> {
    fn page(&self, here: &str, title: &str, body: &str) -> String {
        let mut links = vec![("repos", "Repos"), ("accounts", "Linked accounts"), ("audit", "Audit log")];
        links.push(("account", "Account"));
        if self.user.is_admin {
            links.extend([("users", "Users"), ("audit/all", "All audit")]);
        }
        let mut header = String::from("<header><b>agent-broker</b>");
        for (path, name) in links {
            let class = if path == here { " class=\"here\"" } else { "" };
            header.push_str(&format!("<a{class} href=\"{}/{path}\">{name}</a>", self.base));
        }
        header.push_str(&format!(
            "<form method=\"post\" action=\"{}/logout\">{}<span class=\"muted\">{}</span> \
             <button>Log out</button></form></header>",
            self.base,
            self.csrf_field(),
            esc(&self.user.username)
        ));
        let body = format!("{}{body}", notices(self.ok, self.err));
        document(title, &header, &body)
    }

    fn csrf_field(&self) -> String {
        format!("<input type=\"hidden\" name=\"_csrf\" value=\"{}\">", esc(self.csrf))
    }

    fn form(&self, action: &str, class: &str, inner: &str) -> String {
        format!(
            "<form method=\"post\" action=\"{}/{action}\" class=\"{class}\">{}{inner}</form>",
            self.base,
            self.csrf_field()
        )
    }

    fn button(&self, action: &str, label: &str, danger: bool) -> String {
        let class = if danger { " class=\"danger\"" } else { "" };
        self.form(action, "inline", &format!("<button{class}>{label}</button>"))
    }

    pub fn repos(&self, repos: &[RepoRow], tools: &[&str]) -> String {
        let mut body = String::from("<h1>Repos</h1>");
        if repos.is_empty() {
            body.push_str("<section>No repos yet. Add one below.</section>");
        }
        for repo in repos {
            let state = match (repo.enabled, repo.last_verified) {
                (true, _) => "on",
                (false, None) => "off: the token could not be checked yet",
                (false, Some(_)) => "off",
            };
            let verified = match repo.last_verified {
                Some(time) => format!("token last checked {} UTC", time_text(time)),
                None => "token never checked successfully".to_string(),
            };
            let default = match repo.default_branch.as_str() {
                "" => "unknown".to_string(),
                name => format!("<code>{}</code>", esc(name)),
            };
            let mut edit = format!(
                "<label>Branch prefix</label><input type=\"text\" name=\"prefix\" value=\"{}\" required>\
                 <label>Enabled tools</label>",
                esc(&repo.branch_prefix)
            );
            for tool in tools {
                let checked = if repo.tools.iter().any(|t| t == tool) { " checked" } else { "" };
                edit.push_str(&format!(
                    "<label class=\"check\"><input type=\"checkbox\" name=\"tool\" value=\"{tool}\"{checked}> {tool}</label>"
                ));
            }
            let checked = if repo.enabled { " checked" } else { "" };
            edit.push_str(&format!(
                "<br><label class=\"check\"><input type=\"checkbox\" name=\"enabled\" value=\"1\"{checked}> \
                 Agents may use this repo</label><br><button>Save</button>"
            ));
            let token = "<label>Replace the token</label>\
                 <input type=\"password\" name=\"token\" autocomplete=\"off\" required> <button>Replace</button>";
            body.push_str(&format!(
                "<section><h2>{}</h2><p>{state} &middot; default branch {default} &middot; \
                 <span class=\"muted\">{verified}</span></p>{}{}<p>{}{}</p></section>",
                esc(&repo.full_name),
                self.form(&format!("repos/{}/edit", repo.id), "", &edit),
                self.form(&format!("repos/{}/token", repo.id), "", token),
                self.button(&format!("repos/{}/check", repo.id), "Check the token", false),
                self.button(&format!("repos/{}/delete", repo.id), "Delete this entry", true),
            ));
        }
        let mut add = String::from(
            "<label>Repo, as owner/name</label><input type=\"text\" name=\"repo\" required>\
             <label>Token</label><input type=\"password\" name=\"token\" autocomplete=\"off\" required>\
             <p class=\"muted\">A fine-grained personal access token for this repo only, with \
             Contents and Pull requests set to read and write, and Actions and Commit statuses \
             set to read-only. Do not give it the Workflows permission. It is stored here and \
             never shown again.</p>\
             <label>Branch prefix</label><input type=\"text\" name=\"prefix\" placeholder=\"yourname/\" required>\
             <p class=\"muted\">Agents can only push branches whose names start with this.</p>\
             <label>Enabled tools</label>",
        );
        for tool in tools {
            add.push_str(&format!(
                "<label class=\"check\"><input type=\"checkbox\" name=\"tool\" value=\"{tool}\" checked> {tool}</label>"
            ));
        }
        add.push_str("<br><button>Add repo</button>");
        body.push_str(&format!("<section><h2>Add a repo</h2>{}</section>", self.form("repos/add", "", &add)));
        self.page("repos", "Repos", &body)
    }

    pub fn accounts(
        &self,
        accounts: &[Account],
        claims: &[(u32, String)],
        repos: &[RepoRow],
        code: Option<&str>,
    ) -> String {
        let mut body = String::from("<h1>Linked accounts</h1>");
        if let Some(code) = code {
            body.push_str(&format!(
                "<div class=\"note\">Link code: <code>{}</code><br>It works once, within 10 minutes. \
                 As the unix account to link, run <code>agent-broker link</code> and type the code. \
                 Then come back to this page and confirm.</div>",
                esc(code)
            ));
        }
        for (uid, name) in claims {
            body.push_str(&format!(
                "<section><h2>Waiting for you</h2><p>Unix account <code>{}</code> (uid {uid}) wants to \
                 link to your user. Confirm only if you just ran the link command as that account.</p>{}</section>",
                esc(name),
                self.button(&format!("accounts/{uid}/confirm"), "Confirm", false)
            ));
        }
        if accounts.is_empty() {
            body.push_str("<section>No unix account is linked yet.</section>");
        }
        for account in accounts {
            let checked = if account.all_resources { " checked" } else { "" };
            let mut limits = format!(
                "<label class=\"check\"><input type=\"checkbox\" name=\"all\" value=\"1\"{checked}> \
                 All my repos, including ones added later</label><br>Or only:<br>"
            );
            for repo in repos {
                let checked = if account.resources.contains(&repo.id) { " checked" } else { "" };
                limits.push_str(&format!(
                    "<label class=\"check\"><input type=\"checkbox\" name=\"repo\" value=\"{}\"{checked}> {}</label>",
                    repo.id,
                    esc(&repo.full_name)
                ));
            }
            limits.push_str("<br><button>Save</button>");
            body.push_str(&format!(
                "<section><h2><code>{}</code> (uid {})</h2>{}<p>{}</p></section>",
                esc(&account.unix_name),
                account.uid,
                self.form(&format!("accounts/{}/limits", account.uid), "", &limits),
                self.button(&format!("accounts/{}/unlink", account.uid), "Unlink", true)
            ));
        }
        body.push_str(&format!(
            "<section><h2>Link a unix account</h2><p>Agents run under their own unix accounts. \
             Linking one lets it use your repos through the broker.</p>{}</section>",
            self.button("accounts/code", "Get a link code", false)
        ));
        self.page("accounts", "Linked accounts", &body)
    }

    pub fn audit(&self, rows: &[AuditRow], all: bool, repo: &str, tool: &str) -> String {
        let (here, title) =
            if all { ("audit/all", "Audit log of all users") } else { ("audit", "Audit log") };
        let mut body = format!(
            "<h1>{title}</h1><section><form method=\"get\" action=\"{}/{here}\">\
             <label>Repo</label><input type=\"text\" name=\"repo\" value=\"{}\">\
             <label>Tool</label><input type=\"text\" name=\"tool\" value=\"{}\"> \
             <button>Filter</button></form></section><section><table>\
             <tr><th>Time (UTC)</th><th>Event</th><th>Who</th><th>Repo</th><th>Tool</th><th>Detail</th></tr>",
            self.base,
            esc(repo),
            esc(tool)
        );
        for row in rows {
            let event = match row.ok {
                Some(true) => format!("{} ok", row.event),
                Some(false) => format!("{} failed", row.event),
                None => row.event.clone(),
            };
            let who = match (&row.username, row.uid) {
                (Some(name), Some(uid)) => format!("{name} (uid {uid})"),
                (Some(name), None) => name.clone(),
                (None, Some(uid)) => format!("uid {uid}"),
                (None, None) => String::new(),
            };
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"detail\">{}</td></tr>",
                time_text(row.time),
                esc(&event),
                esc(&who),
                esc(row.resource.as_deref().unwrap_or("")),
                esc(row.tool.as_deref().unwrap_or("")),
                esc(&row.detail)
            ));
        }
        body.push_str("</table>");
        if rows.is_empty() {
            body.push_str("<p>Nothing to show.</p>");
        }
        body.push_str("<p class=\"muted\">The newest 200 entries.</p></section>");
        self.page(here, title, &body)
    }

    pub fn account(&self) -> String {
        let form = "<label>Current password</label><input type=\"password\" name=\"_password\" required>\
             <label>New password (at least 12 characters)</label><input type=\"password\" name=\"new\" required>\
             <label>New password again</label><input type=\"password\" name=\"again\" required>\
             <br><button>Change password</button>";
        let body = format!(
            "<h1>Account</h1><section><h2>Password of {}</h2>{}<p class=\"muted\">Changing it logs out \
             your other sessions.</p></section>",
            esc(&self.user.username),
            self.form("account/password", "", form)
        );
        self.page("account", "Account", &body)
    }

    pub fn users(&self, users: &[User], link: Option<(&str, &str)>) -> String {
        let mut body = String::from("<h1>Users</h1>");
        if let Some((name, url)) = link {
            body.push_str(&format!(
                "<div class=\"note\">One-time link for {}: <code>{}</code><br>It works once, within 15 \
                 minutes, and lets its holder set that user's password. Hand it over safely.</div>",
                esc(name),
                esc(url)
            ));
        }
        body.push_str("<section><table><tr><th>User</th><th>State</th><th></th></tr>");
        for user in users {
            let mut state = vec![];
            if user.is_admin {
                state.push("admin");
            }
            if user.disabled {
                state.push("disabled");
            }
            if !user.has_password {
                state.push("no password yet");
            }
            let id = user.id;
            let mut actions = self.button(&format!("users/{id}/reset"), "Reset link", false);
            if user.id != self.user.id {
                let (path, label) = if user.disabled { ("enable", "Enable") } else { ("disable", "Disable") };
                actions.push_str(&self.button(&format!("users/{id}/{path}"), label, false));
                let (path, label) =
                    if user.is_admin { ("unadmin", "Remove admin") } else { ("admin", "Make admin") };
                actions.push_str(&self.button(&format!("users/{id}/{path}"), label, false));
                actions.push_str(&self.button(&format!("users/{id}/delete"), "Delete", true));
            }
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{actions}</td></tr>",
                esc(&user.username),
                state.join(", ")
            ));
        }
        let add = "<label>Username</label><input type=\"text\" name=\"username\" required> <button>Create user</button>";
        body.push_str(&format!(
            "</table></section><section><h2>Create a user</h2>{}<p class=\"muted\">You get a one-time \
             link to hand over, where the new user sets a password. Deleting a user also deletes their \
             tokens, repo entries and linked accounts.</p></section>",
            self.form("users/add", "", add)
        ));
        self.page("users", "Users", &body)
    }

    /// Asks for the password again before a sensitive change, keeping what was submitted.
    pub fn confirm(&self, action: &str, fields: &[(String, String)], wrong: bool) -> String {
        let mut inner = String::new();
        for (name, value) in fields.iter().filter(|(n, _)| n != "_password" && n != "_csrf") {
            // No page gives a token back, not even the one that was just typed.
            if name == "token" {
                inner.push_str(
                    "<label>The token, once more</label>\
                     <input type=\"password\" name=\"token\" autocomplete=\"off\" required>",
                );
                continue;
            }
            inner.push_str(&format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                esc(name),
                esc(value)
            ));
        }
        inner.push_str(
            "<label>Your password</label><input type=\"password\" name=\"_password\" required autofocus>\
             <br><button>Continue</button>",
        );
        let err = wrong.then_some("That was not the password.");
        let body = format!(
            "{}<h1>Confirm with your password</h1><section><p>This changes who can do what, so it \
             needs your password again.</p>{}</section>",
            notices(None, err),
            self.form(action, "", &inner)
        );
        let plain = Frame { ok: None, err: None, ..*self };
        plain.page("", "Confirm", &body)
    }
}

pub fn login(ok: Option<&str>, err: Option<&str>) -> String {
    let body = format!(
        "<h1>agent-broker</h1>{}<section><form method=\"post\" action=\"/login\">\
         <label>Username</label><input type=\"text\" name=\"username\" required autofocus>\
         <label>Password</label><input type=\"password\" name=\"password\" required>\
         <br><button>Log in</button></form></section>",
        notices(ok, err)
    );
    document("Log in", "", &body)
}

/// The page behind a one-time link: setting the password of `user`, or, without one, creating
/// the first admin. `err` is a name that was typed and what was wrong.
pub fn setup(token: &str, user: Option<&str>, err: Option<(&str, &str)>) -> String {
    let (title, name) = match user {
        Some(user) => (format!("Set the password of {user}"), String::new()),
        None => (
            "Set up agent-broker".to_string(),
            format!(
                "<p>There is no user yet. The one you create here is the first admin.</p>\
                 <label>Username</label><input type=\"text\" name=\"username\" value=\"{}\" required autofocus>",
                esc(err.map_or("", |(typed, _)| typed))
            ),
        ),
    };
    let body = format!(
        "<h1>{}</h1>{}<section><form method=\"post\" action=\"/setup/{}\">{name}\
         <label>New password (at least 12 characters)</label><input type=\"password\" name=\"new\" required>\
         <label>New password again</label><input type=\"password\" name=\"again\" required>\
         <br><button>Set password</button></form></section>",
        esc(&title),
        notices(None, err.map(|(_, problem)| problem)),
        esc(token)
    );
    document(&title, "", &body)
}

pub fn plain(title: &str, text: &str) -> String {
    document(title, "", &format!("<h1>{}</h1><section>{}</section>", esc(title), esc(text)))
}

/// Seconds since 1970 as `YYYY-MM-DD HH:MM:SS`.
pub fn time_text(time: i64) -> String {
    let (days, rest) = (time.div_euclid(86_400), time.rem_euclid(86_400));
    // Days to a civil date, after Howard Hinnant's algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}", rest / 3600, rest % 3600 / 60, rest % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_and_time() {
        assert_eq!(esc("<a href=\"x\">&'"), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
        assert_eq!(time_text(0), "1970-01-01 00:00:00");
        assert_eq!(time_text(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(time_text(1_795_655_712), "2026-11-26 01:15:12");
    }
}

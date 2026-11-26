//! What the web UI reads and writes in the database.

use rusqlite::{OptionalExtension, Row, params};

use crate::db::{Db, hash_secret, now, random_base32};
use crate::error::{Result, refuse};
use crate::github::Found;
use crate::github::rules::check_prefix_spares;

const IDLE: i64 = 30 * 60;
const LIFETIME: i64 = 12 * 60 * 60;
const LINK_LIFETIME: i64 = 15 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
    pub disabled: bool,
    pub has_password: bool,
}

const USER: &str = "id, username, is_admin, disabled, password_hash IS NOT NULL";

fn user(r: &Row) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(0)?,
        username: r.get(1)?,
        is_admin: r.get(2)?,
        disabled: r.get(3)?,
        has_password: r.get(4)?,
    })
}

/// A login that passed the checks of this request.
pub struct Session {
    pub user: User,
    /// When the password was last entered.
    pub last_password: i64,
}

/// A repo entry as its owner sees it. It has no token.
pub struct RepoRow {
    pub id: i64,
    pub full_name: String,
    pub branch_prefix: String,
    pub default_branch: String,
    pub tools: Vec<String>,
    pub enabled: bool,
    pub last_verified: Option<i64>,
    /// For a fork whose pull requests go to the repo it was forked from: that repo and its
    /// default branch. Otherwise empty.
    pub upstream: String,
    pub upstream_default: String,
}

pub struct Account {
    pub uid: u32,
    pub unix_name: String,
    pub all_resources: bool,
    pub resources: Vec<i64>,
}

pub struct AuditRow {
    pub time: i64,
    pub event: String,
    pub uid: Option<u32>,
    pub username: Option<String>,
    pub resource: Option<String>,
    pub tool: Option<String>,
    pub ok: Option<bool>,
    pub detail: String,
}

/// What a successful token check left the entry as.
pub enum Checked {
    On,
    Off,
    /// It had never been usable, and is switched on now.
    FirstOn,
    /// Switched off: this prefix covers that branch, which is a default branch now.
    Covered(String, String),
    /// Switched off: its pull requests are to go to the repo it was forked from, and GitHub
    /// no longer names one.
    NotAFork,
}

/// What the form for a new repo entry said.
pub struct NewRepo<'a> {
    pub token: &'a str,
    /// The repo's name as it was typed.
    pub typed: &'a str,
    pub prefix: &'a str,
    pub tools: &'a [&'a str],
    pub to_upstream: bool,
}

pub enum UserChange {
    Disable,
    Enable,
    Admin(bool),
    Delete,
}

/// 256 random bits, as 52 base32 characters.
fn secret() -> String {
    random_base32(52)
}

impl Db {
    pub fn users(&self) -> Result<Vec<User>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("SELECT {USER} FROM users ORDER BY username"))?;
        let rows = stmt.query_map([], user)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn user(&self, id: i64) -> Result<Option<User>> {
        Ok(self
            .conn()
            .query_row(&format!("SELECT {USER} FROM users WHERE id = ?1"), [id], user)
            .optional()?)
    }

    /// The user and their password hash, for a login attempt.
    pub fn login(&self, username: &str) -> Result<Option<(User, Option<String>)>> {
        Ok(self
            .conn()
            .query_row(
                &format!("SELECT {USER}, password_hash FROM users WHERE username = ?1"),
                [username],
                |r| Ok((user(r)?, r.get(5)?)),
            )
            .optional()?)
    }

    pub fn password_hash(&self, user_id: i64) -> Result<Option<String>> {
        Ok(self
            .conn()
            .query_row("SELECT password_hash FROM users WHERE id = ?1", [user_id], |r| r.get(0))
            .optional()?
            .flatten())
    }

    /// Whether anyone can log in and manage users.
    pub fn has_working_admin(&self) -> Result<bool> {
        Ok(self.conn().query_row(
            "SELECT EXISTS (SELECT 1 FROM users WHERE is_admin AND NOT disabled AND password_hash IS NOT NULL)",
            [],
            |r| r.get(0),
        )?)
    }

    /// Makes `username` an admin who can log in, creating the user if there is none of that
    /// name. Only while nobody can log in and manage users; `false` if somebody can.
    pub fn make_first_admin(&self, username: &str, hash: &str) -> Result<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let working: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM users WHERE is_admin AND NOT disabled AND password_hash IS NOT NULL)",
            [],
            |r| r.get(0),
        )?;
        if working {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO users (username, is_admin, password_hash) VALUES (?1, 1, ?2)
             ON CONFLICT (username) DO UPDATE SET is_admin = 1, disabled = 0, password_hash = ?2",
            params![username, hash],
        )?;
        tx.execute(
            "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?1)",
            [username],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Sets the password and ends every session of the user but `keep`.
    pub fn set_password(&self, user_id: i64, hash: &str, keep: Option<&str>) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("UPDATE users SET password_hash = ?2 WHERE id = ?1", params![user_id, hash])?;
        tx.execute(
            "DELETE FROM sessions WHERE user_id = ?1 AND id_hash IS NOT ?2",
            params![user_id, keep.map(hash_secret)],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Starts a session: (id for the cookie, secret for the URL).
    pub fn create_session(&self, user_id: i64) -> Result<(String, String)> {
        let (id, url_secret) = (secret(), secret());
        let conn = self.conn();
        conn.execute(
            "DELETE FROM sessions WHERE created < ?1 OR last_seen < ?2",
            params![now() - LIFETIME, now() - IDLE],
        )?;
        conn.execute(
            "INSERT INTO sessions VALUES (?1, ?2, ?3, ?4, ?4, ?4)",
            params![hash_secret(&id), hash_secret(&url_secret), user_id, now()],
        )?;
        Ok((id, url_secret))
    }

    /// The session for a cookie and a URL secret, if both fit, it has not run out, and its
    /// user may still log in. Counts as activity.
    pub fn session(&self, id: &str, url_secret: &str) -> Result<Option<Session>> {
        let conn = self.conn();
        let found = conn
            .query_row(
                &format!(
                    "SELECT {USER}, s.last_password FROM sessions s JOIN users ON users.id = s.user_id
                     WHERE s.id_hash = ?1 AND s.secret_hash = ?2 AND s.last_seen > ?3 AND s.created > ?4"
                ),
                params![hash_secret(id), hash_secret(url_secret), now() - IDLE, now() - LIFETIME],
                |r| Ok(Session { user: user(r)?, last_password: r.get(5)? }),
            )
            .optional()?
            .filter(|s| !s.user.disabled);
        if found.is_some() {
            conn.execute(
                "UPDATE sessions SET last_seen = ?2 WHERE id_hash = ?1",
                params![hash_secret(id), now()],
            )?;
        }
        Ok(found)
    }

    pub fn password_entered(&self, id: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE sessions SET last_password = ?2 WHERE id_hash = ?1",
            params![hash_secret(id), now()],
        )?;
        Ok(())
    }

    pub fn end_session(&self, id: &str) -> Result<()> {
        self.conn().execute("DELETE FROM sessions WHERE id_hash = ?1", [hash_secret(id)])?;
        Ok(())
    }

    /// A single-use link token to set a password. Earlier unused ones of the user end, and so
    /// do the user's sessions: a link is asked for when the password is lost or no longer
    /// trusted, and then whoever is logged in with it should not stay.
    pub fn new_one_time_link(&self, user_id: i64, purpose: &str) -> Result<String> {
        let token = secret();
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM one_time_links WHERE user_id = ?1 OR expires < ?2", params![user_id, now()])?;
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?;
        tx.execute(
            "INSERT INTO one_time_links (token_hash, user_id, purpose, expires) VALUES (?1, ?2, ?3, ?4)",
            params![hash_secret(&token), user_id, purpose, now() + LINK_LIFETIME],
        )?;
        tx.commit()?;
        Ok(token)
    }

    /// The user a link token is for, if it is still good.
    pub fn one_time_link(&self, token: &str) -> Result<Option<User>> {
        Ok(self
            .conn()
            .query_row(
                &format!(
                    "SELECT {USER} FROM one_time_links l JOIN users ON users.id = l.user_id
                     WHERE l.token_hash = ?1 AND NOT l.used AND l.expires > ?2"
                ),
                params![hash_secret(token), now()],
                user,
            )
            .optional()?)
    }

    /// Sets the password through a link token, which is used up by it.
    pub fn use_one_time_link(&self, token: &str, hash: &str) -> Result<Option<User>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let used = tx.execute(
            "UPDATE one_time_links SET used = 1 WHERE token_hash = ?1 AND NOT used AND expires > ?2",
            params![hash_secret(token), now()],
        )?;
        if used == 0 {
            return Ok(None);
        }
        let found = tx.query_row(
            &format!(
                "SELECT {USER} FROM one_time_links l JOIN users ON users.id = l.user_id
                 WHERE l.token_hash = ?1"
            ),
            [hash_secret(token)],
            user,
        )?;
        tx.execute("UPDATE users SET password_hash = ?2 WHERE id = ?1", params![found.id, hash])?;
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", [found.id])?;
        tx.commit()?;
        Ok(Some(found))
    }

    pub fn repo_rows(&self, user_id: i64) -> Result<Vec<RepoRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT r.id, g.full_name, g.branch_prefix, g.default_branch, r.enabled_tools, r.enabled,
                    c.last_verified, g.upstream, g.upstream_default
             FROM resources r
             JOIN github_repo_entries g ON g.resource_id = r.id
             JOIN credentials c ON c.id = r.credential_id
             WHERE r.user_id = ?1 ORDER BY g.full_name",
        )?;
        let rows = stmt.query_map([user_id], |r| {
            let tools: String = r.get(4)?;
            Ok(RepoRow {
                id: r.get(0)?,
                full_name: r.get(1)?,
                branch_prefix: r.get(2)?,
                default_branch: r.get(3)?,
                tools: tools.split(' ').filter(|t| !t.is_empty()).map(Into::into).collect(),
                enabled: r.get(5)?,
                last_verified: r.get(6)?,
                upstream: r.get(7)?,
                upstream_default: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn repo_row(&self, user_id: i64, id: i64) -> Result<RepoRow> {
        match self.repo_rows(user_id)?.into_iter().find(|r| r.id == id) {
            Some(row) => Ok(row),
            None => refuse("no such repo entry"),
        }
    }

    /// The token of a user's own repo entry, to check it against GitHub. Never for display.
    pub fn repo_token(&self, user_id: i64, id: i64) -> Result<String> {
        let token = self
            .conn()
            .query_row(
                "SELECT c.token FROM resources r JOIN credentials c ON c.id = r.credential_id
                 WHERE r.user_id = ?1 AND r.id = ?2",
                params![user_id, id],
                |r| r.get(0),
            )
            .optional()?;
        token.map_or_else(|| refuse("no such repo entry"), Ok)
    }

    /// Adds a repo entry under the name GitHub gave, or under `typed` if the token could not
    /// read the repo; then the entry starts switched off. With `to_upstream` its pull requests
    /// go to the repo it was forked from, which only GitHub can name.
    pub fn add_repo(&self, user_id: i64, new: &NewRepo, found: Option<&Found>) -> Result<i64> {
        let NewRepo { token, typed, prefix, tools, to_upstream } = *new;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let parent = found.and_then(|f| f.parent.as_ref()).filter(|_| to_upstream);
        if to_upstream && parent.is_none() {
            return refuse(match found {
                Some(found) => format!("GitHub does not say that {} is a fork. Nothing was stored.", found.full_name),
                None => "The token could not read the repo, so the repo it was forked from is not known. Nothing was stored.".into(),
            });
        }
        if let Some(found) = found {
            check_prefix_spares(prefix, &found.default_branch)?;
        }
        if let Some((_, default_branch)) = parent {
            check_prefix_spares(prefix, default_branch)?;
        }
        let id = Self::insert_github_repo(
            &tx,
            user_id,
            token,
            found.map_or(typed, |f| &f.full_name),
            prefix,
            found.map_or("", |f| &f.default_branch),
            tools,
        )?;
        if let Some((upstream, default_branch)) = parent {
            tx.execute(
                "UPDATE github_repo_entries SET upstream = ?2, upstream_default = ?3 WHERE resource_id = ?1",
                params![id, upstream, default_branch],
            )?;
        }
        match found {
            Some(_) => tx.execute(
                "UPDATE credentials SET last_verified = ?2
                 WHERE id = (SELECT credential_id FROM resources WHERE id = ?1)",
                params![id, now()],
            )?,
            None => tx.execute("UPDATE resources SET enabled = 0 WHERE id = ?1", [id])?,
        };
        tx.commit()?;
        Ok(id)
    }

    /// Changes an entry's rules. The prefix is checked here, against the default branch as it
    /// is stored at this moment, so that a token check running at the same time cannot be
    /// overruled by what a form was filled in with earlier.
    pub fn update_repo(
        &self,
        user_id: i64,
        id: i64,
        prefix: &str,
        tools: &[&str],
        enabled: bool,
    ) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let defaults: Option<(String, String)> = tx
            .query_row(
                "SELECT g.default_branch, g.upstream_default
                 FROM github_repo_entries g JOIN resources r ON r.id = g.resource_id
                 WHERE r.user_id = ?1 AND r.id = ?2",
                params![user_id, id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((default_branch, upstream_default)) = defaults else {
            return refuse("no such repo entry");
        };
        check_prefix_spares(prefix, &default_branch)?;
        check_prefix_spares(prefix, &upstream_default)?;
        if enabled && default_branch.is_empty() {
            return refuse("This entry stays off until \"Check the token\" succeeds.");
        }
        tx.execute(
            "UPDATE resources SET enabled_tools = ?3, enabled = ?4 WHERE user_id = ?1 AND id = ?2",
            params![user_id, id, tools.join(" "), enabled],
        )?;
        tx.execute(
            "UPDATE github_repo_entries SET branch_prefix = ?2 WHERE resource_id = ?1",
            params![id, prefix],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Stores a replacement token that could not read the repo. The old one is gone, so the
    /// entry is switched off until a check succeeds and its owner switches it on again.
    pub fn set_unchecked_token(&self, user_id: i64, id: i64, token: &str) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE credentials SET token = ?3, last_verified = NULL
             WHERE id = (SELECT credential_id FROM resources WHERE user_id = ?1 AND id = ?2)",
            params![user_id, id, token],
        )?;
        if changed == 0 {
            return refuse("no such repo entry");
        }
        tx.execute("UPDATE resources SET enabled = 0 WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    /// Records what GitHub said about the repo when a token could read it: the stored one, or
    /// `new_token`, which then replaces it. The entry's rules are held against that answer in
    /// the same step.
    pub fn set_repo_checked(
        &self,
        user_id: i64,
        id: i64,
        new_token: Option<&str>,
        found: &Found,
    ) -> Result<Checked> {
        let (full_name, default_branch) = (found.full_name.as_str(), found.default_branch.as_str());
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE credentials SET last_verified = ?3, label = ?4, token = coalesce(?5, token)
             WHERE id = (SELECT credential_id FROM resources WHERE user_id = ?1 AND id = ?2)",
            params![user_id, id, now(), full_name, new_token],
        )?;
        if changed == 0 {
            return refuse("no such repo entry");
        }
        // A rename on GitHub can make two entries mean the same repo. One repo, one set of rules.
        let duplicate: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM github_repo_entries g JOIN resources r ON r.id = g.resource_id
             WHERE r.user_id = ?1 AND g.full_name = ?2 AND r.id <> ?3)",
            params![user_id, full_name, id],
            |r| r.get(0),
        )?;
        if duplicate {
            return refuse(format!(
                "GitHub calls this repo {full_name} now, and there is another entry for that. Delete one of the two."
            ));
        }
        let (prefix, was_default, enabled, upstream): (String, String, bool, String) = tx.query_row(
            "SELECT g.branch_prefix, g.default_branch, r.enabled, g.upstream
             FROM github_repo_entries g JOIN resources r ON r.id = g.resource_id WHERE r.id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        // Only an entry that was added as a fork has its pull requests go elsewhere.
        let parent = found.parent.as_ref().filter(|_| !upstream.is_empty());
        if let Some((upstream, upstream_default)) = parent {
            tx.execute(
                "UPDATE github_repo_entries SET upstream = ?2, upstream_default = ?3 WHERE resource_id = ?1",
                params![id, upstream, upstream_default],
            )?;
        }
        let covered = [Some(default_branch), parent.map(|(_, branch)| branch.as_str())]
            .into_iter()
            .flatten()
            .find(|branch| check_prefix_spares(&prefix, branch).is_err());
        tx.execute(
            "UPDATE github_repo_entries SET full_name = ?2, default_branch = ?3 WHERE resource_id = ?1",
            params![id, full_name, default_branch],
        )?;
        let (checked, on) = if !upstream.is_empty() && parent.is_none() {
            (Checked::NotAFork, false)
        } else if let Some(branch) = covered {
            (Checked::Covered(prefix, branch.to_string()), false)
        } else if was_default.is_empty() {
            (Checked::FirstOn, true)
        } else if enabled {
            (Checked::On, true)
        } else {
            (Checked::Off, false)
        };
        tx.execute("UPDATE resources SET enabled = ?2 WHERE id = ?1", params![id, on])?;
        tx.commit()?;
        Ok(checked)
    }

    pub fn delete_repo(&self, user_id: i64, id: i64) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let credential: Option<i64> = tx
            .query_row(
                "SELECT credential_id FROM resources WHERE user_id = ?1 AND id = ?2",
                params![user_id, id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(credential) = credential else { return refuse("no such repo entry") };
        tx.execute("DELETE FROM resources WHERE id = ?1", [id])?;
        tx.execute(
            "DELETE FROM credentials WHERE id = ?1
             AND NOT EXISTS (SELECT 1 FROM resources WHERE credential_id = ?1)",
            [credential],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The ids of a user's repo entries, which name their mirrors.
    pub fn resource_ids(&self, user_id: i64) -> Result<Vec<i64>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT id FROM resources WHERE user_id = ?1")?;
        let rows = stmt.query_map([user_id], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn accounts(&self, user_id: i64) -> Result<Vec<Account>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT uid, unix_name, all_resources FROM linked_accounts WHERE user_id = ?1 ORDER BY unix_name",
        )?;
        let mut limits = conn.prepare("SELECT resource_id FROM linked_account_resources WHERE uid = ?1")?;
        let rows = stmt.query_map([user_id], |r| {
            Ok(Account { uid: r.get(0)?, unix_name: r.get(1)?, all_resources: r.get(2)?, resources: vec![] })
        })?;
        let mut accounts: Vec<Account> = rows.collect::<rusqlite::Result<_>>()?;
        for account in &mut accounts {
            let ids = limits.query_map([account.uid], |r| r.get(0))?;
            account.resources = ids.collect::<rusqlite::Result<_>>()?;
        }
        Ok(accounts)
    }

    /// Accounts that presented one of the user's codes and wait to be confirmed.
    pub fn pending_claims(&self, user_id: i64) -> Result<Vec<(u32, String)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT claimed_uid, claimed_name FROM link_codes
             WHERE user_id = ?1 AND claimed_uid IS NOT NULL AND NOT confirmed AND expires > ?2
             ORDER BY id",
        )?;
        let rows = stmt.query_map(params![user_id, now()], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn unlink(&self, user_id: i64, uid: u32) -> Result<()> {
        let changed = self
            .conn()
            .execute("DELETE FROM linked_accounts WHERE user_id = ?1 AND uid = ?2", params![user_id, uid])?;
        if changed == 0 {
            return refuse("no such linked account");
        }
        Ok(())
    }

    /// Which of the user's repos a linked account may use: all, or the listed ones.
    pub fn set_account_limits(&self, user_id: i64, uid: u32, all: bool, resources: &[i64]) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE linked_accounts SET all_resources = ?3 WHERE user_id = ?1 AND uid = ?2",
            params![user_id, uid, all],
        )?;
        if changed == 0 {
            return refuse("no such linked account");
        }
        tx.execute("DELETE FROM linked_account_resources WHERE uid = ?1", [uid])?;
        for id in resources {
            // Only the user's own repos, whatever the form said.
            tx.execute(
                "INSERT OR IGNORE INTO linked_account_resources
                 SELECT ?1, id FROM resources WHERE id = ?2 AND user_id = ?3",
                params![uid, id, user_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The newest audit entries: of one user, or of everyone if `username` is `None`.
    pub fn audit_page(
        &self,
        username: Option<&str>,
        resource: Option<&str>,
        tool: Option<&str>,
        limit: u32,
    ) -> Result<Vec<AuditRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT time, event, uid, username, resource, tool, ok, detail FROM audit
             WHERE (?1 IS NULL OR username = ?1) AND (?2 IS NULL OR resource = ?2)
               AND (?3 IS NULL OR tool = ?3)
             ORDER BY id DESC LIMIT ?4",
        )?;
        let rows = stmt.query_map(params![username, resource, tool, limit], |r| {
            Ok(AuditRow {
                time: r.get(0)?,
                event: r.get(1)?,
                uid: r.get(2)?,
                username: r.get(3)?,
                resource: r.get(4)?,
                tool: r.get(5)?,
                ok: r.get(6)?,
                detail: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Changes or deletes a user. Someone must remain who can manage users, and that is
    /// looked at in the same step as the change: two admins cannot remove each other.
    ///
    /// A deleted user's audit entries stay, under a name no later user can have: someone who
    /// is given the same username must not find them in their own log.
    pub fn change_user(&self, id: i64, change: UserChange) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = match change {
            UserChange::Disable => {
                tx.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
                tx.execute("UPDATE users SET disabled = 1 WHERE id = ?1", [id])?
            }
            UserChange::Enable => tx.execute("UPDATE users SET disabled = 0 WHERE id = ?1", [id])?,
            UserChange::Admin(is_admin) => {
                tx.execute("UPDATE users SET is_admin = ?2 WHERE id = ?1", params![id, is_admin])?
            }
            UserChange::Delete => {
                tx.execute(
                    "UPDATE audit SET username = username || ' (deleted)'
                     WHERE username = (SELECT username FROM users WHERE id = ?1)",
                    [id],
                )?;
                tx.execute("DELETE FROM users WHERE id = ?1", [id])?
            }
        };
        if changed == 0 {
            return refuse("no such user");
        }
        let admins: i64 =
            tx.query_row("SELECT count(*) FROM users WHERE is_admin AND NOT disabled", [], |r| r.get(0))?;
        if admins == 0 {
            return refuse("That would leave no admin.");
        }
        tx.commit()?;
        Ok(())
    }
}

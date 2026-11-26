//! What the web UI reads and writes in the database.

use rusqlite::{OptionalExtension, Row, params};

use crate::db::{Db, hash_secret, now, random_base32};
use crate::error::{Result, refuse};

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
        conn.execute("DELETE FROM sessions WHERE created < ?1", [now() - LIFETIME])?;
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

    /// A single-use link token to set a password. Earlier unused ones of the user end.
    pub fn new_one_time_link(&self, user_id: i64, purpose: &str) -> Result<String> {
        let token = secret();
        let conn = self.conn();
        conn.execute(
            "DELETE FROM one_time_links WHERE user_id = ?1 OR expires < ?2",
            params![user_id, now()],
        )?;
        conn.execute(
            "INSERT INTO one_time_links (token_hash, user_id, purpose, expires) VALUES (?1, ?2, ?3, ?4)",
            params![hash_secret(&token), user_id, purpose, now() + LINK_LIFETIME],
        )?;
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
                    c.last_verified
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
        let changed = tx.execute(
            "UPDATE resources SET enabled_tools = ?3, enabled = ?4 WHERE user_id = ?1 AND id = ?2",
            params![user_id, id, tools.join(" "), enabled],
        )?;
        if changed == 0 {
            return refuse("no such repo entry");
        }
        tx.execute(
            "UPDATE github_repo_entries SET branch_prefix = ?2 WHERE resource_id = ?1",
            params![id, prefix],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_repo_enabled(&self, user_id: i64, id: i64, enabled: bool) -> Result<()> {
        self.conn().execute(
            "UPDATE resources SET enabled = ?3 WHERE user_id = ?1 AND id = ?2",
            params![user_id, id, enabled],
        )?;
        Ok(())
    }

    pub fn set_repo_token(&self, user_id: i64, id: i64, token: &str) -> Result<()> {
        let changed = self.conn().execute(
            "UPDATE credentials SET token = ?3, last_verified = NULL
             WHERE id = (SELECT credential_id FROM resources WHERE user_id = ?1 AND id = ?2)",
            params![user_id, id, token],
        )?;
        if changed == 0 {
            return refuse("no such repo entry");
        }
        Ok(())
    }

    /// Records what GitHub said about the repo when the token was last checked.
    pub fn set_repo_verified(
        &self,
        user_id: i64,
        id: i64,
        full_name: &str,
        default_branch: &str,
    ) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE credentials SET last_verified = ?3, label = ?4
             WHERE id = (SELECT credential_id FROM resources WHERE user_id = ?1 AND id = ?2)",
            params![user_id, id, now(), full_name],
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
        tx.execute(
            "UPDATE github_repo_entries SET full_name = ?2, default_branch = ?3 WHERE resource_id = ?1",
            params![id, full_name, default_branch],
        )?;
        tx.commit()?;
        Ok(())
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

    pub fn set_user_disabled(&self, id: i64, disabled: bool) -> Result<()> {
        let conn = self.conn();
        conn.execute("UPDATE users SET disabled = ?2 WHERE id = ?1", params![id, disabled])?;
        if disabled {
            conn.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
        }
        Ok(())
    }

    pub fn set_user_admin(&self, id: i64, is_admin: bool) -> Result<()> {
        self.conn().execute("UPDATE users SET is_admin = ?2 WHERE id = ?1", params![id, is_admin])?;
        Ok(())
    }

    /// Deletes a user. Their audit entries stay, under a name no later user can have: someone
    /// who is given the same username must not find them in their own log.
    pub fn delete_user(&self, id: i64) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE audit SET username = username || ' (deleted)'
             WHERE username = (SELECT username FROM users WHERE id = ?1)",
            [id],
        )?;
        tx.execute("DELETE FROM users WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    /// Admins who can log in.
    pub fn active_admins(&self) -> Result<i64> {
        Ok(self
            .conn()
            .query_row("SELECT count(*) FROM users WHERE is_admin AND NOT disabled", [], |r| r.get(0))?)
    }
}

//! The daemon's database.

use std::fs::{OpenOptions, Permissions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{Result, refuse};

pub const DEFAULT_MAX_BLOB: u64 = 512 * 1024 * 1024;
pub const LINK_CODE_LIFETIME: i64 = 600;

const SCHEMA: &str = "
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    totp_secret TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE credentials (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    service TEXT NOT NULL,
    label TEXT NOT NULL,
    -- Plain text: a key to decrypt it would sit on the same disk.
    token TEXT NOT NULL,
    login TEXT,
    expires TEXT,
    last_verified INTEGER
);
CREATE TABLE resources (
    -- Ids name mirror directories, so one must never be reused.
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    service TEXT NOT NULL,
    credential_id INTEGER NOT NULL REFERENCES credentials,
    enabled_tools TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE github_repo_entries (
    resource_id INTEGER PRIMARY KEY REFERENCES resources ON DELETE CASCADE,
    full_name TEXT NOT NULL COLLATE NOCASE,
    branch_prefix TEXT NOT NULL,
    default_branch TEXT NOT NULL
);
CREATE TABLE github_created_branches (
    resource_id INTEGER NOT NULL REFERENCES resources ON DELETE CASCADE,
    branch TEXT NOT NULL,
    -- the commit the broker last pushed there; NULL if recorded before this was kept
    tip TEXT,
    PRIMARY KEY (resource_id, branch)
);
CREATE TABLE linked_accounts (
    uid INTEGER PRIMARY KEY,
    unix_name TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    label TEXT NOT NULL DEFAULT '',
    all_resources INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE linked_account_resources (
    uid INTEGER NOT NULL REFERENCES linked_accounts ON DELETE CASCADE,
    resource_id INTEGER NOT NULL REFERENCES resources ON DELETE CASCADE,
    PRIMARY KEY (uid, resource_id)
);
CREATE TABLE link_codes (
    id INTEGER PRIMARY KEY,
    code_hash BLOB NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    expires INTEGER NOT NULL,
    claimed_uid INTEGER,
    claimed_name TEXT,
    confirmed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE audit (
    id INTEGER PRIMARY KEY,
    time INTEGER NOT NULL,
    -- start, end and refused for tool calls; other names for everything else
    event TEXT NOT NULL,
    call_id TEXT,
    uid INTEGER,
    -- Copied rather than referenced: entries outlive users and repos.
    username TEXT,
    resource TEXT,
    tool TEXT,
    ok INTEGER,
    detail TEXT NOT NULL
);
CREATE TABLE settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
";

const SCHEMA_VERSION: i64 = 2;

pub struct Db {
    conn: Mutex<Connection>,
}

/// The user a caller acts for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub uid: u32,
    pub user_id: i64,
    pub username: String,
    pub all_resources: bool,
}

/// One GitHub repo as configured by one user. Deliberately not `Debug`: it holds the token.
#[derive(Clone)]
pub struct RepoEntry {
    pub resource_id: i64,
    pub full_name: String,
    pub branch_prefix: String,
    pub default_branch: String,
    pub enabled_tools: Vec<String>,
    pub token: String,
}

impl RepoEntry {
    pub fn owner(&self) -> &str {
        self.full_name.split('/').next().unwrap_or("")
    }
}

#[derive(Default)]
pub struct AuditEntry<'a> {
    pub event: &'a str,
    pub call_id: Option<&'a str>,
    pub uid: Option<u32>,
    pub username: Option<&'a str>,
    pub resource: Option<&'a str>,
    pub tool: Option<&'a str>,
    pub ok: Option<bool>,
    pub detail: &'a str,
}

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

pub fn hash_secret(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

/// Random bytes in lower-case Crockford base32, which has no look-alike letters.
pub fn random_base32(chars: usize) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut bytes = vec![0u8; chars];
    getrandom::fill(&mut bytes).expect("the kernel provides randomness");
    bytes.iter().map(|b| ALPHABET[(b & 31) as usize] as char).collect()
}

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        // Create it ourselves so that it is never readable by others, whatever the umask.
        OpenOptions::new().create(true).append(true).mode(0o600).open(path)?;
        // The mode above only counts for a new file. SQLite gives its side files the mode
        // of the database, so this goes first.
        for suffix in ["", "-wal", "-shm"] {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            match std::fs::set_permissions(&name, Permissions::from_mode(0o600)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
        }
        let mut conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", true)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        match version {
            0 => {
                tx.execute_batch(SCHEMA)?;
                tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            }
            1 => {
                tx.execute_batch("ALTER TABLE github_created_branches ADD COLUMN tip TEXT")?;
                tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            }
            SCHEMA_VERSION => {}
            v => return refuse(format!("database has unknown version {v}")),
        }
        tx.commit()?;
        Ok(Db { conn: Mutex::new(conn) })
    }

    pub fn conn(&self) -> MutexGuard<'_, Connection> {
        // Transactions roll back on unwind, so the connection stays usable after a panic.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn max_blob(&self) -> Result<u64> {
        let v: Option<String> = self
            .conn()
            .query_row("SELECT value FROM settings WHERE name = 'max_blob'", [], |r| r.get(0))
            .optional()?;
        Ok(v.and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_MAX_BLOB))
    }

    /// Resolves a uid. `None` means unlinked. `current_name` is the uid's account name now; if
    /// it differs from the one at link time the uid was reused.
    pub fn caller(&self, uid: u32, current_name: Option<&str>) -> Result<Option<Caller>> {
        let row = self
            .conn()
            .query_row(
                "SELECT l.unix_name, u.id, u.username, l.all_resources, u.disabled
                 FROM linked_accounts l JOIN users u ON u.id = l.user_id WHERE l.uid = ?1",
                [uid],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        Caller { uid, user_id: r.get(1)?, username: r.get(2)?, all_resources: r.get(3)? },
                        r.get::<_, bool>(4)?,
                    ))
                },
            )
            .optional()?;
        Ok(row
            .filter(|(name, _, disabled)| current_name == Some(name) && !disabled)
            .map(|(_, caller, _)| caller))
    }

    /// The enabled repo entries the caller may use.
    pub fn repos(&self, caller: &Caller) -> Result<Vec<RepoEntry>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT r.id, g.full_name, g.branch_prefix, g.default_branch, r.enabled_tools, c.token
             FROM resources r
             JOIN github_repo_entries g ON g.resource_id = r.id
             JOIN credentials c ON c.id = r.credential_id AND c.user_id = r.user_id
             WHERE r.user_id = ?1 AND r.enabled AND (?2 OR EXISTS (
                 SELECT 1 FROM linked_account_resources l
                 WHERE l.uid = ?3 AND l.resource_id = r.id))
             ORDER BY g.full_name",
        )?;
        let rows = stmt.query_map(params![caller.user_id, caller.all_resources, caller.uid], |r| {
            let tools: String = r.get(4)?;
            Ok(RepoEntry {
                resource_id: r.get(0)?,
                full_name: r.get(1)?,
                branch_prefix: r.get(2)?,
                default_branch: r.get(3)?,
                enabled_tools: tools.split(' ').filter(|t| !t.is_empty()).map(Into::into).collect(),
                token: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// For a branch that was created through the broker: the commit the broker last pushed
    /// there, if known. `None` if the branch was not created through the broker.
    pub fn created_branch(&self, resource_id: i64, branch: &str) -> Result<Option<Option<String>>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT tip FROM github_created_branches WHERE resource_id = ?1 AND branch = ?2",
                params![resource_id, branch],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Records that the broker created `branch` at `tip`.
    pub fn record_branch(&self, resource_id: i64, branch: &str, tip: &str) -> Result<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO github_created_branches (resource_id, branch, tip)
             VALUES (?1, ?2, ?3)",
            params![resource_id, branch, tip],
        )?;
        Ok(())
    }

    /// Records a later push to a branch the broker created; does nothing for other branches.
    pub fn record_push(&self, resource_id: i64, branch: &str, tip: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE github_created_branches SET tip = ?3 WHERE resource_id = ?1 AND branch = ?2",
            params![resource_id, branch, tip],
        )?;
        Ok(())
    }

    pub fn audit(&self, e: &AuditEntry) -> Result<()> {
        self.conn().execute(
            "INSERT INTO audit (time, event, call_id, uid, username, resource, tool, ok, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![now(), e.event, e.call_id, e.uid, e.username, e.resource, e.tool, e.ok, e.detail],
        )?;
        Ok(())
    }

    pub fn add_user(&self, username: &str, is_admin: bool) -> Result<i64> {
        let conn = self.conn();
        conn.execute("INSERT INTO users (username, is_admin) VALUES (?1, ?2)", params![username, is_admin])?;
        Ok(conn.last_insert_rowid())
    }

    pub fn user_id(&self, username: &str) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row("SELECT id FROM users WHERE username = ?1", [username], |r| r.get(0))
            .optional()?)
    }

    pub fn add_github_repo(
        &self,
        user_id: i64,
        token: &str,
        full_name: &str,
        branch_prefix: &str,
        default_branch: &str,
        tools: &[&str],
    ) -> Result<i64> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let duplicate: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM github_repo_entries g JOIN resources r
             ON r.id = g.resource_id WHERE r.user_id = ?1 AND g.full_name = ?2)",
            params![user_id, full_name],
            |r| r.get(0),
        )?;
        if duplicate {
            return refuse(format!("{full_name} is already configured"));
        }
        tx.execute(
            "INSERT INTO credentials (user_id, service, label, token)
             VALUES (?1, 'github', ?2, ?3)",
            params![user_id, full_name, token],
        )?;
        let credential = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO resources (user_id, service, credential_id, enabled_tools)
             VALUES (?1, 'github', ?2, ?3)",
            params![user_id, credential, tools.join(" ")],
        )?;
        let resource = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO github_repo_entries VALUES (?1, ?2, ?3, ?4)",
            params![resource, full_name, branch_prefix, default_branch],
        )?;
        tx.commit()?;
        Ok(resource)
    }

    /// Creates a single-use link code (50 bits).
    pub fn new_link_code(&self, user_id: i64) -> Result<String> {
        let code = random_base32(10);
        self.conn().execute(
            "INSERT INTO link_codes (code_hash, user_id, expires) VALUES (?1, ?2, ?3)",
            params![hash_secret(&code), user_id, now() + LINK_CODE_LIFETIME],
        )?;
        Ok(code)
    }

    /// Records that `uid` presented a code. The link only becomes active on confirmation.
    pub fn claim_link_code(&self, code: &str, uid: u32, name: &str) -> Result<()> {
        let code: String =
            code.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase();
        let conn = self.conn();
        let linked: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM linked_accounts WHERE uid = ?1 AND unix_name = ?2)",
            params![uid, name],
            |r| r.get(0),
        )?;
        if linked {
            return refuse("this unix account is already linked; unlink it in the web UI first");
        }
        let changed = conn.execute(
            "UPDATE link_codes SET claimed_uid = ?2, claimed_name = ?3
             WHERE code_hash = ?1 AND claimed_uid IS NULL AND expires > ?4",
            params![hash_secret(&code), uid, name, now()],
        )?;
        if changed == 0 {
            return refuse("unknown, used or expired link code");
        }
        Ok(())
    }

    /// Activates the claim made with `code` by the user it was issued to.
    pub fn confirm_link(&self, user_id: i64, uid: u32) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let claim: Option<(i64, String)> = tx
            .query_row(
                "SELECT id, claimed_name FROM link_codes
                 WHERE user_id = ?1 AND claimed_uid = ?2 AND NOT confirmed AND expires > ?3
                 ORDER BY id DESC LIMIT 1",
                params![user_id, uid, now()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((id, name)) = claim else {
            return refuse("no unexpired claim by this account");
        };
        let linked: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM linked_accounts WHERE uid = ?1 AND unix_name = ?2)",
            params![uid, name],
            |r| r.get(0),
        )?;
        if linked {
            return refuse("this unix account is already linked");
        }
        // A link left over from a deleted account whose uid was reused is replaced.
        tx.execute("DELETE FROM linked_accounts WHERE uid = ?1 AND unix_name <> ?2", params![uid, name])?;
        tx.execute(
            "INSERT INTO linked_accounts (uid, unix_name, user_id) VALUES (?1, ?2, ?3)",
            params![uid, name, user_id],
        )?;
        tx.execute("UPDATE link_codes SET confirmed = 1 WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    /// Audit rows as JSON, oldest first.
    pub fn audit_rows(&self) -> Result<Vec<Value>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT event, call_id, uid, username, resource, tool, ok, detail
             FROM audit ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(serde_json::json!({
                "event": r.get::<_, String>(0)?, "call_id": r.get::<_, Option<String>>(1)?,
                "uid": r.get::<_, Option<u32>>(2)?, "username": r.get::<_, Option<String>>(3)?,
                "resource": r.get::<_, Option<String>>(4)?, "tool": r.get::<_, Option<String>>(5)?,
                "ok": r.get::<_, Option<bool>>(6)?, "detail": r.get::<_, String>(7)?,
            }))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("db")).unwrap();
        (dir, db)
    }

    fn link(db: &Db, user: i64, uid: u32, name: &str) {
        let code = db.new_link_code(user).unwrap();
        db.claim_link_code(&code, uid, name).unwrap();
        assert_eq!(db.caller(uid, Some(name)).unwrap(), None, "a claim alone must not link");
        db.confirm_link(user, uid).unwrap();
    }

    #[test]
    fn caller_resolution() {
        let (_d, db) = db();
        let alice = db.add_user("alice", false).unwrap();
        link(&db, alice, 5001, "agent1");
        assert_eq!(db.caller(5001, Some("agent1")).unwrap().unwrap().username, "alice");
        assert!(db.caller(5001, Some("other")).unwrap().is_none(), "reused uid");
        assert!(db.caller(5001, None).unwrap().is_none());
        assert!(db.caller(5002, Some("agent1")).unwrap().is_none());
        db.conn().execute("UPDATE users SET disabled = 1", []).unwrap();
        assert!(db.caller(5001, Some("agent1")).unwrap().is_none());
    }

    #[test]
    fn repos_are_limited_to_the_caller() {
        let (_d, db) = db();
        let alice = db.add_user("alice", false).unwrap();
        let bob = db.add_user("bob", false).unwrap();
        let a = db.add_github_repo(alice, "t", "o/a", "a/", "main", &["github_push"]).unwrap();
        db.add_github_repo(alice, "t", "o/b", "a/", "main", &[]).unwrap();
        db.add_github_repo(bob, "t", "o/c", "b/", "main", &[]).unwrap();
        link(&db, alice, 5001, "agent1");
        link(&db, bob, 5002, "agent2");
        let names = |uid, name| -> Vec<String> {
            let c = db.caller(uid, Some(name)).unwrap().unwrap();
            db.repos(&c).unwrap().into_iter().map(|r| r.full_name).collect()
        };
        assert_eq!(names(5001, "agent1"), ["o/a", "o/b"]);
        assert_eq!(names(5002, "agent2"), ["o/c"]);
        db.conn().execute("UPDATE linked_accounts SET all_resources = 0 WHERE uid = 5001", []).unwrap();
        assert!(names(5001, "agent1").is_empty());
        db.conn().execute("INSERT INTO linked_account_resources VALUES (5001, ?1)", [a]).unwrap();
        assert_eq!(names(5001, "agent1"), ["o/a"]);
        db.conn().execute("UPDATE resources SET enabled = 0", []).unwrap();
        assert!(names(5001, "agent1").is_empty());
        assert!(db.add_github_repo(alice, "t", "O/A", "a/", "main", &[]).is_err());
    }

    #[test]
    fn link_codes() {
        let (_d, db) = db();
        let alice = db.add_user("alice", false).unwrap();
        let bob = db.add_user("bob", false).unwrap();
        let code = db.new_link_code(alice).unwrap();
        assert!(db.claim_link_code("0000000000", 5001, "a").is_err());
        let typed = format!("{}-{}", code[..5].to_uppercase(), &code[5..]);
        db.claim_link_code(&typed, 5001, "a").unwrap();
        assert!(db.claim_link_code(&code, 5002, "b").is_err(), "single use");
        assert!(db.confirm_link(bob, 5001).is_err(), "only the user who got the code");
        db.confirm_link(alice, 5001).unwrap();
        let again = db.new_link_code(bob).unwrap();
        assert!(db.claim_link_code(&again, 5001, "a").is_err(), "one user per account");
        db.conn().execute("UPDATE link_codes SET expires = 0", []).unwrap();
        assert!(db.claim_link_code(&again, 5003, "c").is_err(), "expired");
        let stale = db.new_link_code(bob).unwrap();
        db.claim_link_code(&stale, 5004, "d").unwrap();
        db.conn().execute("UPDATE link_codes SET expires = 0", []).unwrap();
        assert!(db.confirm_link(bob, 5004).is_err());
    }

    #[test]
    fn a_second_claim_by_a_linked_account_is_refused_on_confirmation() {
        let (_dir, db) = db();
        let user = db.add_user("alice", false).unwrap();
        for _ in 0..2 {
            let code = db.new_link_code(user).unwrap();
            db.claim_link_code(&code, 1001, "agent").unwrap();
        }
        db.confirm_link(user, 1001).unwrap();
        let again = db.confirm_link(user, 1001).unwrap_err();
        assert_eq!(again.public(), "this unix account is already linked");
        assert!(db.caller(1001, Some("agent")).unwrap().is_some());
    }

    #[test]
    fn the_newest_claim_of_a_uid_is_the_one_confirmed() {
        // The uid went from a deleted account to a new one while the first code was valid.
        let (_dir, db) = db();
        let user = db.add_user("alice", false).unwrap();
        for name in ["old", "new"] {
            let code = db.new_link_code(user).unwrap();
            db.claim_link_code(&code, 1001, name).unwrap();
        }
        db.confirm_link(user, 1001).unwrap();
        assert!(db.caller(1001, Some("new")).unwrap().is_some());
        assert_eq!(db.caller(1001, Some("old")).unwrap(), None);
    }

    #[test]
    fn created_branches_remember_what_was_pushed() {
        let (_dir, db) = db();
        let user = db.add_user("alice", false).unwrap();
        let repo = db.add_github_repo(user, "t", "o/a", "a/", "main", &[]).unwrap();
        assert_eq!(db.created_branch(repo, "a/x").unwrap(), None);
        // Only branches the broker created are tracked.
        db.record_push(repo, "a/x", "1111").unwrap();
        assert_eq!(db.created_branch(repo, "a/x").unwrap(), None);
        db.record_branch(repo, "a/x", "1111").unwrap();
        db.record_push(repo, "a/x", "2222").unwrap();
        assert_eq!(db.created_branch(repo, "a/x").unwrap(), Some(Some("2222".into())));
        db.record_branch(repo, "a/x", "3333").unwrap();
        assert_eq!(db.created_branch(repo, "a/x").unwrap(), Some(Some("3333".into())));
    }

    #[test]
    fn a_version_1_database_is_brought_up_to_date() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let repo = {
            let db = Db::open(&path).unwrap();
            let user = db.add_user("alice", false).unwrap();
            let repo = db.add_github_repo(user, "t", "o/a", "a/", "main", &[]).unwrap();
            db.record_branch(repo, "a/x", "1111").unwrap();
            // Back to how version 1 stored it.
            let conn = db.conn();
            conn.execute_batch("ALTER TABLE github_created_branches DROP COLUMN tip").unwrap();
            conn.pragma_update(None, "user_version", 1).unwrap();
            repo
        };
        let db = Db::open(&path).unwrap();
        // Known as created, but with nothing to compare against, so force is refused.
        assert_eq!(db.created_branch(repo, "a/x").unwrap(), Some(None));
        db.record_push(repo, "a/x", "2222").unwrap();
        assert_eq!(db.created_branch(repo, "a/x").unwrap(), Some(Some("2222".into())));
        drop(db);
        Db::open(&path).unwrap();
    }

    #[test]
    fn file_is_private() {
        let (d, db) = db();
        db.add_user("x", false).unwrap();
        let private = || {
            for f in std::fs::read_dir(d.path()).unwrap() {
                let mode = f.unwrap().metadata().unwrap().permissions().mode();
                assert_eq!(mode & 0o077, 0);
            }
        };
        private();
        // A file that was opened up is closed again.
        drop(db);
        let path = d.path().join("db");
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        let db = Db::open(&path).unwrap();
        db.add_user("y", false).unwrap();
        private();
    }
}

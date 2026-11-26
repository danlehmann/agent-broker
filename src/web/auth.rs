//! Passwords and the delay after failed logins.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};

pub const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1024;

/// How expensive hashing is. Tests use a cheap setting.
#[derive(Clone, Copy)]
pub struct Cost {
    pub memory_kib: u32,
    pub passes: u32,
}

impl Default for Cost {
    fn default() -> Self {
        Cost { memory_kib: Params::DEFAULT_M_COST, passes: Params::DEFAULT_T_COST }
    }
}

fn argon2id(password: &str, salt: &[u8], memory_kib: u32, passes: u32) -> Option<Vec<u8>> {
    let params = Params::new(memory_kib, passes, 1, Some(32)).ok()?;
    let mut out = vec![0; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .ok()?;
    Some(out)
}

/// Why a new password is not acceptable, if it is not.
pub fn check_new_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!("the password needs at least {MIN_PASSWORD_CHARS} characters"));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err("the password is too long".into());
    }
    Ok(())
}

/// A hash to store: `argon2id$<memory>$<passes>$<salt>$<hash>`.
pub fn hash_password(password: &str, cost: Cost) -> Option<String> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).ok()?;
    let hash = argon2id(password, &salt, cost.memory_kib, cost.passes)?;
    let (salt, hash) = (STANDARD_NO_PAD.encode(salt), STANDARD_NO_PAD.encode(hash));
    Some(format!("argon2id${}${}${salt}${hash}", cost.memory_kib, cost.passes))
}

/// Whether the password fits the stored hash. Without a stored hash it still does the work
/// of hashing, so that the time taken does not tell whether the user exists.
pub fn verify_password(password: &str, stored: Option<&str>, cost: Cost) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    let parsed = stored.and_then(|stored| {
        let mut parts = stored.split('$');
        let ("argon2id", memory, passes, salt, hash, None) =
            (parts.next()?, parts.next()?, parts.next()?, parts.next()?, parts.next()?, parts.next())
        else {
            return None;
        };
        let (salt, hash) = (STANDARD_NO_PAD.decode(salt).ok()?, STANDARD_NO_PAD.decode(hash).ok()?);
        Some((memory.parse().ok()?, passes.parse().ok()?, salt, hash))
    });
    match parsed {
        Some((memory, passes, salt, hash)) => {
            argon2id(password, &salt, memory, passes).is_some_and(|computed| same(&computed, &hash))
        }
        None => {
            let _ = argon2id(password, &[0; 16], cost.memory_kib, cost.passes);
            false
        }
    }
}

/// Compares without stopping at the first difference.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Slows down guessing, per unix account that asks and username it asks for. There is no
/// lockout, and one account's failures do not delay another's attempts: every local account
/// can reach the login, so an agent could otherwise keep people out.
#[derive(Default)]
pub struct Delays {
    failures: Mutex<HashMap<(u32, String), (u32, Instant)>>,
}

const MAX_DELAY: Duration = Duration::from_secs(60);
const MAX_TRACKED: usize = 10_000;
/// Longer names are not names of users; see `check_username`.
pub const MAX_USERNAME_BYTES: usize = 64;

impl Delays {
    fn key(peer: u32, username: &str) -> Option<(u32, String)> {
        (username.len() <= MAX_USERNAME_BYTES).then(|| (peer, username.to_string()))
    }

    /// How long the next attempt still has to wait.
    pub fn wait(&self, peer: u32, username: &str) -> Option<Duration> {
        let failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let (_, until) = failures.get(&Self::key(peer, username)?)?;
        Some(until.saturating_duration_since(Instant::now())).filter(|d| !d.is_zero())
    }

    /// One second after the first failure, doubling up to a minute.
    pub fn failed(&self, peer: u32, username: &str) {
        let Some(key) = Self::key(peer, username) else { return };
        let mut failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if failures.len() >= MAX_TRACKED {
            failures.retain(|_, (_, until)| *until + MAX_DELAY * 10 > now);
        }
        if failures.len() >= MAX_TRACKED {
            failures.clear();
        }
        let entry = failures.entry(key).or_insert((0, now));
        // Long quiet: start over.
        if entry.1 + MAX_DELAY * 10 < now {
            entry.0 = 0;
        }
        entry.0 = entry.0.saturating_add(1);
        let delay = Duration::from_secs(1u64 << (entry.0 - 1).min(6)).min(MAX_DELAY);
        entry.1 = now + delay;
    }

    pub fn succeeded(&self, peer: u32, username: &str) {
        if let Some(key) = Self::key(peer, username) {
            self.failures.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHEAP: Cost = Cost { memory_kib: 8, passes: 1 };

    #[test]
    fn passwords() {
        let stored = hash_password("correct horse battery", CHEAP).unwrap();
        assert!(stored.starts_with("argon2id$8$1$"));
        assert!(verify_password("correct horse battery", Some(&stored), CHEAP));
        assert!(!verify_password("correct horse batterz", Some(&stored), CHEAP));
        assert!(!verify_password("", Some(&stored), CHEAP));
        assert_ne!(stored, hash_password("correct horse battery", CHEAP).unwrap(), "salted");
        for broken in ["", "argon2id$8$1$x", "plain", "argon2id$8$1$!!$!!", &format!("{stored}$more")] {
            assert!(!verify_password("correct horse battery", Some(broken), CHEAP), "{broken}");
        }
        assert!(!verify_password("x", None, CHEAP));
        assert!(check_new_password("twelve chars").is_ok());
        assert!(check_new_password("eleven char").is_err());
        assert!(check_new_password(&"x".repeat(2000)).is_err());
        assert!(same(b"abc", b"abc") && !same(b"abc", b"abd") && !same(b"abc", b"ab"));
    }

    #[test]
    fn delays_grow_and_end() {
        let delays = Delays::default();
        assert_eq!(delays.wait(1, "a"), None);
        delays.failed(1, "a");
        let first = delays.wait(1, "a").unwrap();
        assert!(first <= Duration::from_secs(1));
        for _ in 0..10 {
            delays.failed(1, "a");
        }
        let later = delays.wait(1, "a").unwrap();
        assert!(later > Duration::from_secs(50) && later <= MAX_DELAY);
        assert_eq!(delays.wait(1, "b"), None, "per name");
        assert_eq!(delays.wait(2, "a"), None, "per account that asks");
        delays.succeeded(2, "a");
        assert!(delays.wait(1, "a").is_some());
        delays.succeeded(1, "a");
        assert_eq!(delays.wait(1, "a"), None);
        // Names that cannot be usernames are not kept.
        let long = "x".repeat(MAX_USERNAME_BYTES + 1);
        delays.failed(1, &long);
        assert!(delays.failures.lock().unwrap().is_empty());
    }
}

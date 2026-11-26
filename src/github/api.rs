//! GitHub's REST API.

use std::cell::Cell;
use std::io::Read;
use std::time::Duration;

use serde_json::Value;
use ureq::http::{Request, Response};

use super::{Endpoints, GitHub};
use crate::db::RepoEntry;
use crate::error::{Result, refuse};
use crate::scrub::head;

const MAX_JSON: u64 = 20 * 1024 * 1024;
const MAX_LOG: u64 = 64 * 1024 * 1024;
const PAGE: usize = 100;
const MAX_PAGES: usize = 5;
const MAX_REDIRECTS: usize = 3;

pub fn agent(endpoints: &Endpoints) -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(endpoints.api.starts_with("https://"))
        // Redirects are followed by hand so that the token never goes to another host.
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(60)))
        .user_agent("agent-broker")
        .build()
        .into()
}

pub struct Api<'a> {
    gh: &'a GitHub,
    pub entry: &'a RepoEntry,
    /// Requests made so far for this tool call.
    requests: Cell<u32>,
}

/// How many requests one tool call may make. A list of lists can otherwise grow into
/// thousands of them.
const MAX_REQUESTS: u32 = 60;

impl GitHub {
    pub(super) fn api<'a>(&'a self, entry: &'a RepoEntry) -> Api<'a> {
        Api { gh: self, entry, requests: Cell::new(0) }
    }
}

/// A string field, or "" if it is null or missing.
pub fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The start of a list.
pub struct Paged {
    pub items: Vec<Value>,
    /// GitHub has more than was read.
    pub cut: bool,
}

/// How many entries of a list are read at most.
pub const MAX_ITEMS: usize = PAGE * MAX_PAGES;

/// Scheme, host and port of a URL.
fn origin(url: &str) -> Option<&str> {
    let start = url.find("://")? + 3;
    let end = url[start..].find(['/', '?', '#']).map_or(url.len(), |i| start + i);
    Some(&url[..end])
}

impl Api<'_> {
    pub fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<Value> {
        self.json("GET", path, query, None)
    }

    pub fn send(&self, method: &str, path: &str, body: &Value) -> Result<Value> {
        self.json(method, path, &[], Some(body))
    }

    /// All items of a list, up to [`MAX_PAGES`] pages. `key` names the list if it is wrapped
    /// in an object.
    pub fn paged(&self, path: &str, query: &[(&str, &str)], key: Option<&str>) -> Result<Paged> {
        let mut items = Vec::new();
        let mut all_full = true;
        for page in 1..=MAX_PAGES {
            let (per_page, page) = (PAGE.to_string(), page.to_string());
            let mut query = query.to_vec();
            query.extend([("per_page", &*per_page), ("page", &*page)]);
            let mut reply = self.get(path, &query)?;
            let list = match key {
                Some(key) => reply[key].take(),
                None => reply,
            };
            let list = match list {
                Value::Array(list) => list,
                _ => vec![],
            };
            let full = list.len() >= PAGE;
            items.extend(list);
            if !full {
                all_full = false;
                break;
            }
        }
        // Exactly as many as are read is not "more": ask for the one after the last.
        let cut = all_full && {
            let after = (MAX_ITEMS + 1).to_string();
            let mut query = query.to_vec();
            query.extend([("per_page", "1"), ("page", &*after)]);
            match self.get(path, &query) {
                Ok(mut reply) => {
                    let next = match key {
                        Some(key) => reply[key].take(),
                        None => reply,
                    };
                    next.as_array().is_some_and(|list| !list.is_empty())
                }
                // What was read is still worth having; say that there may be more.
                Err(_) => true,
            }
        };
        Ok(Paged { items, cut })
    }

    /// A plain-text resource that GitHub serves from a storage host.
    pub fn log(&self, path: &str) -> Result<String> {
        let body = self.request("GET", path, &[], None, MAX_LOG)?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }

    fn json(&self, method: &str, path: &str, query: &[(&str, &str)], body: Option<&Value>) -> Result<Value> {
        let bytes = self.request(method, path, query, body, MAX_JSON)?;
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes)
            .or_else(|_| refuse(format!("GitHub {method} {}: reply is not JSON", self.full_path(path))))
    }

    fn full_path(&self, path: &str) -> String {
        format!("/repos/{}{path}", self.entry.full_name)
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&Value>,
        limit: u64,
    ) -> Result<Vec<u8>> {
        let path = self.full_path(path);
        let fail = |why: String| refuse(format!("GitHub {method} {path}: {why}"));
        let mut url = format!("{}{path}", self.gh.endpoints.api);
        for (i, (k, v)) in query.iter().enumerate() {
            url.push(if i == 0 { '?' } else { '&' });
            url.push_str(&format!("{k}={}", encode(v)));
        }
        let mut redirects = 0;
        loop {
            self.requests.set(self.requests.get() + 1);
            if self.requests.get() > MAX_REQUESTS {
                return fail(format!(
                    "this call needs more than {MAX_REQUESTS} requests to GitHub; ask for something narrower"
                ));
            }
            let with_token = origin(&url) == origin(&self.gh.endpoints.api);
            let mut response = match self.once(method, &url, body, with_token) {
                Ok(r) => r,
                // Not the error's own URL or host: a redirect target may carry a signature.
                Err(e) => return fail(describe(&e)),
            };
            let status = response.status();
            if status.is_redirection() && method == "GET" && redirects < MAX_REDIRECTS {
                let target = response.headers().get("location").and_then(|l| l.to_str().ok());
                let Some(target) = target else { return fail("redirect without a target".into()) };
                url = if target.starts_with('/') && !target.starts_with("//") {
                    format!("{}{target}", origin(&url).unwrap_or(""))
                } else if target.starts_with("https://") || target.starts_with("http://") {
                    target.to_string()
                } else {
                    return fail("redirect to a target that is not supported".into());
                };
                redirects += 1;
                continue;
            }
            let mut bytes = Vec::new();
            let read = response.body_mut().as_reader().take(limit + 1).read_to_end(&mut bytes);
            if let Err(e) = read {
                return fail(format!("reading the reply failed ({})", e.kind()));
            }
            if !status.is_success() {
                let text = head(&String::from_utf8_lossy(&bytes), 2000);
                return fail(format!("HTTP {}: {text}", status.as_u16()));
            }
            if bytes.len() as u64 > limit {
                return fail("reply is too large".into());
            }
            return Ok(bytes);
        }
    }

    fn once(
        &self,
        method: &str,
        url: &str,
        body: Option<&Value>,
        with_token: bool,
    ) -> std::result::Result<Response<ureq::Body>, ureq::Error> {
        let mut request = Request::builder().method(method).uri(url);
        if with_token {
            request = request
                .header("Authorization", format!("Bearer {}", self.entry.token))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28");
        }
        match body {
            Some(body) => {
                self.gh.http.run(request.header("Content-Type", "application/json").body(body.to_string())?)
            }
            None => self.gh.http.run(request.body(())?),
        }
    }
}

fn describe(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Timeout(_) => "timed out".into(),
        ureq::Error::HostNotFound => "host not found".into(),
        ureq::Error::ConnectionFailed => "connection failed".into(),
        ureq::Error::Io(e) => format!("connection failed ({})", e.kind()),
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => "TLS failed".into(),
        _ => "request failed".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_helpers() {
        assert_eq!(encode("o:daniel/x y&z"), "o%3Adaniel%2Fx%20y%26z");
        assert_eq!(origin("https://api.github.com/x"), Some("https://api.github.com"));
        assert_ne!(origin("https://api.github.com.evil/x"), origin("https://api.github.com/x"));
        assert_ne!(origin("https://api.github.com@evil/x"), origin("https://api.github.com/x"));
        assert_ne!(origin("http://api.github.com/x"), origin("https://api.github.com/x"));
        assert_eq!(origin("nonsense"), None);
    }
}

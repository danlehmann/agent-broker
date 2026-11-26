//! Between the socket and [`Web::handle`]: reading requests, writing replies.
//!
//! Small on purpose: one request per connection, no chunked bodies, and limits on size, time
//! and on how many connections one unix account may hold. Every local account can connect to
//! the socket, so none of them may be able to keep the others out.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{Req, Resp, Web};
use crate::dispatch::log;

const MAX_HEAD: usize = 16 * 1024;
const MAX_FORM: usize = 64 * 1024;
/// For one read or write, and for a whole request to arrive.
const STEP: Duration = Duration::from_secs(10);
const WHOLE: Duration = Duration::from_secs(20);
const MAX_PER_UID: usize = 4;
const MAX_IN_ALL: usize = 32;

/// Percent-encodes for a query string.
pub fn encode(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |at: usize| bytes.get(at).and_then(|b| (*b as char).to_digit(16));
        match (bytes[i], hex(i + 1), hex(i + 2)) {
            (b'%', Some(high), Some(low)) => {
                out.push((high * 16 + low) as u8);
                i += 2;
            }
            (b'+', _, _) => out.push(b' '),
            (b, _, _) => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The fields of a query string or a form.
pub fn pairs(text: &str) -> Vec<(String, String)> {
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(name), decode(value))
        })
        .collect()
}

/// Reads until `enough` says so, within the size and the time allowed.
fn read_until(
    stream: &mut &UnixStream,
    buffer: &mut Vec<u8>,
    max: usize,
    deadline: Instant,
    enough: impl Fn(&[u8]) -> bool,
) -> Option<()> {
    let mut chunk = [0; 4096];
    while !enough(buffer) {
        if buffer.len() > max || Instant::now() >= deadline {
            return None;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return None,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some(())
}

/// Reads one request. `None` for anything this server does not take.
fn read(mut stream: &UnixStream, peer: u32) -> Option<Req> {
    let deadline = Instant::now() + WHOLE;
    let mut buffer = Vec::new();
    let end = |b: &[u8]| b.windows(4).position(|w| w == b"\r\n\r\n");
    read_until(&mut stream, &mut buffer, MAX_HEAD, deadline, |b| end(b).is_some())?;
    let head_len = end(&buffer)?;
    let head = String::from_utf8(buffer[..head_len].to_vec()).ok()?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target, version) = (first.next()?, first.next()?, first.next()?);
    if first.next().is_some() || !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return None;
    }
    let mut headers: HashMap<String, &str> = HashMap::new();
    for line in lines {
        let (name, value) = line.split_once(':')?;
        // The same header twice could mean two things; take neither.
        if headers.insert(name.trim().to_ascii_lowercase(), value.trim()).is_some() {
            return None;
        }
    }
    if headers.contains_key("transfer-encoding") {
        return None;
    }
    let length: usize = match headers.get("content-length") {
        Some(length) => length.parse().ok()?,
        None => 0,
    };
    if length > MAX_FORM {
        return None;
    }
    let body_start = head_len + 4;
    let wanted = body_start + length;
    read_until(&mut stream, &mut buffer, wanted, deadline, |b| b.len() >= wanted)?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let form = match method {
        "POST" => pairs(&String::from_utf8_lossy(&buffer[body_start..wanted])),
        _ => vec![],
    };
    Some(Req {
        method: method.to_string(),
        path: path.to_string(),
        query: pairs(query),
        host: headers.get("host")?.to_string(),
        origin: headers.get("origin").map(|o| o.to_string()),
        cookies: headers.get("cookie").copied().unwrap_or_default().to_string(),
        form,
        peer,
    })
}

fn respond(mut stream: &UnixStream, resp: &Resp) {
    let reason = match resp.status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    };
    // No scripts, no outside content, no framing, nothing kept by the browser. The referrer
    // stays within the site: with none at all, browsers send forms with the origin "null".
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Connection: close\r\nCache-Control: no-store\r\nReferrer-Policy: same-origin\r\n\
         X-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; \
         style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\n",
        resp.status,
        resp.body.len()
    );
    // Both are made here from base32 and percent-encoded text, so they hold no line break.
    if let Some(location) = &resp.location {
        head.push_str(&format!("Location: {location}\r\n"));
    }
    if let Some(cookie) = &resp.set_cookie {
        head.push_str(&format!("Set-Cookie: {cookie}\r\n"));
    }
    head.push_str("\r\n");
    // The path holds the session's secret, so a failure is not logged with it.
    let _ = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(resp.body.as_bytes()));
}

/// Connections being served, per unix account.
#[derive(Default)]
struct Slots(Mutex<HashMap<u32, usize>>);

/// One connection's place. Dropping it frees the place, also when its thread panics.
struct Slot {
    slots: Arc<Slots>,
    uid: u32,
}

impl Slots {
    fn take(self: &Arc<Self>, uid: u32) -> Option<Slot> {
        let mut held = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if held.values().sum::<usize>() >= MAX_IN_ALL || held.get(&uid).copied().unwrap_or(0) >= MAX_PER_UID {
            return None;
        }
        *held.entry(uid).or_insert(0) += 1;
        Some(Slot { slots: self.clone(), uid })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut held = self.slots.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = held.get_mut(&self.uid) {
            *n -= 1;
            if *n == 0 {
                held.remove(&self.uid);
            }
        }
    }
}

/// Takes in what the caller is still sending, for a moment. Closing with unread input makes
/// the kernel reset the connection, and the caller would lose the reply that says why.
fn drain(mut stream: &UnixStream) -> std::io::Result<()> {
    stream.shutdown(std::net::Shutdown::Write)?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut chunk = [0; 4096];
    let mut left = 4 * MAX_FORM;
    while left > 0 {
        match stream.read(&mut chunk)? {
            0 => break,
            n => left = left.saturating_sub(n),
        }
    }
    Ok(())
}

fn plain(status: u16, text: &str) -> Resp {
    Resp { status, body: text.into(), ..Default::default() }
}

/// Serves the web UI on a unix socket until the listener fails for good.
pub fn serve(web: Arc<Web>, listener: UnixListener) {
    let slots = Arc::new(Slots::default());
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(e) => {
                log(&format!("web: accept: {e}"), None);
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let _ = stream.set_read_timeout(Some(STEP));
        let _ = stream.set_write_timeout(Some(STEP));
        let Ok(peer) = web.broker.identity.peer_uid(&stream) else { continue };
        let Some(slot) = slots.take(peer) else {
            respond(&stream, &plain(503, "busy; try again"));
            continue;
        };
        let web = web.clone();
        std::thread::spawn(move || {
            let _slot = slot;
            let req = read(&stream, peer);
            let resp = match &req {
                Some(req) => web.handle(req),
                None => plain(400, "bad request"),
            };
            respond(&stream, &resp);
            if req.is_none() {
                let _ = drain(&stream);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms() {
        let got = pairs("a=1&b=x+y%21&tool=t1&tool=t2&empty=&bare&%zz=%4");
        let want = [
            ("a", "1"),
            ("b", "x y!"),
            ("tool", "t1"),
            ("tool", "t2"),
            ("empty", ""),
            ("bare", ""),
            ("%zz", "%4"),
        ];
        let want: Vec<(String, String)> = want.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        assert_eq!(got, want);
        assert_eq!(decode(&encode("a b&c=d/é\n")), "a b&c=d/é\n");
        assert_eq!(encode("a b"), "a%20b");
    }

    #[test]
    fn slots_are_limited_per_account_and_given_back() {
        let slots = Arc::new(Slots::default());
        let mine: Vec<Slot> = (0..MAX_PER_UID).map(|_| slots.take(1).unwrap()).collect();
        assert!(slots.take(1).is_none(), "one account cannot take them all");
        let theirs = slots.take(2).unwrap();
        drop(mine);
        assert!(slots.take(1).is_some());
        drop(theirs);
        let all: Vec<Slot> = (0..MAX_IN_ALL as u32).map(|uid| slots.take(100 + uid).unwrap()).collect();
        assert!(slots.take(1).is_none());
        drop(all);
        assert!(slots.0.lock().unwrap().is_empty());
        // A thread that panics gives its slot back too.
        let slot = slots.take(1).unwrap();
        let _ = std::thread::spawn(move || {
            let _slot = slot;
            panic!("as a handler might");
        })
        .join();
        assert!(slots.0.lock().unwrap().is_empty());
    }
}

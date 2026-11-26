//! Between the socket and [`Web::handle`]: reading requests, writing replies.

use std::io::Read;
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tiny_http::{Header, Request, Response, Server};

use super::{Req, Resp, Web};
use crate::dispatch::log;

const MAX_FORM: u64 = 64 * 1024;
const MAX_BUSY: usize = 8;

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

fn read(request: &mut Request) -> Option<Req> {
    let header = |name: &'static str| {
        request.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str().to_string())
    };
    let url = request.url().to_string();
    let (path, query) = url.split_once('?').unwrap_or((&url, ""));
    let mut req = Req {
        method: request.method().as_str().to_string(),
        path: path.to_string(),
        query: pairs(query),
        host: header("Host")?,
        origin: header("Origin"),
        cookies: header("Cookie").unwrap_or_default(),
        form: vec![],
    };
    if req.method == "POST" {
        let mut body = Vec::new();
        request.as_reader().take(MAX_FORM + 1).read_to_end(&mut body).ok()?;
        if body.len() as u64 > MAX_FORM {
            return None;
        }
        req.form = pairs(&String::from_utf8_lossy(&body));
    }
    Some(req)
}

fn respond(request: Request, resp: Resp) {
    // No scripts, no outside content, no framing; nothing is kept or passed on by the browser.
    let mut headers = vec![
        ("Content-Type", "text/html; charset=utf-8".to_string()),
        ("Cache-Control", "no-store".to_string()),
        ("Referrer-Policy", "no-referrer".to_string()),
        ("X-Content-Type-Options", "nosniff".to_string()),
        (
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
                .to_string(),
        ),
    ];
    if let Some(location) = resp.location {
        headers.push(("Location", location));
    }
    if let Some(cookie) = resp.set_cookie {
        headers.push(("Set-Cookie", cookie));
    }
    let mut response = Response::from_string(resp.body).with_status_code(resp.status);
    for (name, value) in headers {
        if let Ok(header) = Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            response.add_header(header);
        }
    }
    // The path holds the session's secret, so a failure is logged without it.
    if let Err(e) = request.respond(response) {
        log(&format!("web: sending a reply failed ({})", e.kind()), None);
    }
}

/// Serves the web UI on a unix socket until the listener fails.
pub fn serve(web: Arc<Web>, listener: UnixListener) {
    let server = match Server::from_listener(listener, None) {
        Ok(server) => server,
        Err(e) => return log(&format!("web: cannot serve: {e}"), None),
    };
    let busy = Arc::new(AtomicUsize::new(0));
    for mut request in server.incoming_requests() {
        // Hashing a password takes memory and time; a few at once are enough.
        if busy.fetch_add(1, Ordering::SeqCst) >= MAX_BUSY {
            busy.fetch_sub(1, Ordering::SeqCst);
            respond(request, Resp { status: 503, body: "busy; try again".into(), ..Default::default() });
            continue;
        }
        let (web, busy) = (web.clone(), busy.clone());
        std::thread::spawn(move || {
            let resp = match read(&mut request) {
                Some(req) => web.handle(&req),
                None => Resp { status: 400, body: "bad request".into(), ..Default::default() },
            };
            respond(request, resp);
            busy.fetch_sub(1, Ordering::SeqCst);
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
}

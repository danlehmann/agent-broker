//! A daemon with a local directory as GitHub's git side and a fake API server.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use agent_broker::daemon;
use agent_broker::db::Db;
use agent_broker::dispatch::Broker;
use agent_broker::github::{Endpoints, GitHub, TOOLS};
use agent_broker::platform::Identity;
use agent_broker::shim::Shim;
use serde_json::{Value, json};

pub const TOKEN: &str = "secretTokenOfAlice";
pub const ALICE: u32 = 5001;
pub const BOB: u32 = 5002;
pub const STRANGER: u32 = 5003;

/// Pretends that connections come from whichever uid the test chose.
struct FakeIdentity(Arc<AtomicU32>);

impl Identity for FakeIdentity {
    fn peer_uid(&self, _: &UnixStream) -> std::io::Result<u32> {
        Ok(self.0.load(Ordering::SeqCst))
    }
    fn account_name(&self, uid: u32) -> Option<String> {
        Some(format!("agent{uid}"))
    }
}

pub struct Request {
    pub method: String,
    pub target: String,
    pub headers: String,
    pub body: String,
}

/// Canned replies by "METHOD target"; anything else is a 404. A target without its query
/// matches too.
#[derive(Default)]
pub struct FakeApi {
    pub replies: Mutex<HashMap<String, (u16, String, String)>>,
    pub seen: Mutex<Vec<Request>>,
}

impl FakeApi {
    pub fn start() -> (Arc<FakeApi>, String) {
        let api = Arc::new(FakeApi::default());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let shared = api.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let api = shared.clone();
                std::thread::spawn(move || api.serve(stream));
            }
        });
        (api, url)
    }

    fn serve(&self, stream: TcpStream) -> Option<()> {
        let mut reader = BufReader::new(stream);
        let mut first = String::new();
        reader.read_line(&mut first).ok()?;
        let mut parts = first.split(' ');
        let (method, target) = (parts.next()?.to_string(), parts.next()?.to_string());
        let mut headers = String::new();
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).ok()?;
            if line.trim().is_empty() {
                break;
            }
            let lower = line.to_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                length = v.trim().parse().ok()?;
            }
            headers.push_str(&lower);
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).ok()?;
        let body = String::from_utf8(body).ok()?;
        let path = target.split('?').next()?;
        let reply = {
            let replies = self.replies.lock().unwrap();
            replies
                .get(&format!("{method} {target}"))
                .or(replies.get(&format!("{method} {path}")))
                .cloned()
                .unwrap_or((404, String::new(), "no such thing".into()))
        };
        let (status, header, text) = reply;
        // A hostile or careless server repeats what it was sent.
        let text = text.replace("ECHO", &headers);
        self.seen.lock().unwrap().push(Request { method, target, headers, body });
        let mut stream = reader.into_inner();
        write!(
            stream,
            "HTTP/1.1 {status} X\r\n{header}Content-Length: {}\r\nConnection: close\r\n\r\n{text}",
            text.len()
        )
        .ok()
    }

    pub fn on(&self, request: &str, reply: Value) {
        self.raw(request, 200, "", &reply.to_string());
    }

    pub fn raw(&self, request: &str, status: u16, header: &str, body: &str) {
        self.replies.lock().unwrap().insert(request.into(), (status, header.into(), body.into()));
    }

    pub fn writes(&self) -> Vec<String> {
        let seen = self.seen.lock().unwrap();
        seen.iter().filter(|r| r.method != "GET").map(|r| format!("{} {}", r.method, r.target)).collect()
    }
}

pub struct World {
    pub dir: tempfile::TempDir,
    pub broker: Arc<Broker>,
    pub api: Arc<FakeApi>,
    pub storage: Arc<FakeApi>,
    pub storage_url: String,
    pub socket_dir: PathBuf,
    pub alice_repo: i64,
    uid: Arc<AtomicU32>,
}

pub fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().trim().into()
}

impl World {
    pub fn new() -> World {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let socket_dir = dir.path().join("run");
        for d in ["data", "run", "hub/o", "data/tmp"] {
            daemon::create_private_dir(&dir.path().join(d)).unwrap();
        }
        let db = Db::open(&data.join("broker.db")).unwrap();
        let tools: Vec<&str> = TOOLS.iter().map(|t| t.name).collect();
        let mut ids = vec![];
        for (user, uid, token, repo) in [("alice", ALICE, TOKEN, "o/a"), ("bob", BOB, "bobToken", "o/b")] {
            let id = db.add_user(user, false).unwrap();
            ids.push(db.add_github_repo(id, token, repo, "daniel/", "main", &tools).unwrap());
            let code = db.new_link_code(id).unwrap();
            db.claim_link_code(&code, uid, &format!("agent{uid}")).unwrap();
            db.confirm_link(id, uid).unwrap();
            let bare = dir.path().join(format!("hub/{repo}.git"));
            git(dir.path(), &["init", "-q", "--bare", "-b", "main", bare.to_str().unwrap()]);
            // As GitHub does.
            git(&bare, &["config", "uploadpack.allowAnySHA1InWant", "true"]);
        }
        let (api, url) = FakeApi::start();
        let (storage, storage_url) = FakeApi::start();
        let endpoints = Endpoints { api: url, git: format!("file://{}/hub/", dir.path().display()) };
        let github = GitHub::new(endpoints, &data, dir.path().to_path_buf());
        let uid = Arc::new(AtomicU32::new(ALICE));
        let broker = Arc::new(Broker::new(db, github, Box::new(FakeIdentity(uid.clone())), 4999));
        let listener = UnixListener::bind(socket_dir.join("agent.sock")).unwrap();
        let shared = broker.clone();
        std::thread::spawn(move || daemon::serve(&shared, &listener));
        let world = World { dir, broker, api, storage, storage_url, socket_dir, alice_repo: ids[0], uid };

        let seed = world.checkout("seed");
        git(&seed, &["checkout", "-q", "-b", "main"]);
        world.commit(&seed, "base");
        for repo in ["o/a", "o/b"] {
            git(&seed, &["push", "-q", world.hub(repo).to_str().unwrap(), "main"]);
        }
        world
    }

    pub fn become_uid(&self, uid: u32) {
        self.uid.store(uid, Ordering::SeqCst);
    }

    pub fn socket(&self) -> PathBuf {
        self.socket_dir.join("agent.sock")
    }

    pub fn hub(&self, repo: &str) -> PathBuf {
        self.dir.path().join(format!("hub/{repo}.git"))
    }

    pub fn mirror(&self) -> PathBuf {
        self.dir.path().join(format!("data/mirrors/{}.git", self.alice_repo))
    }

    /// An empty repository for an agent.
    pub fn checkout(&self, name: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        git(self.dir.path(), &["init", "-q", "-b", "unused", path.to_str().unwrap()]);
        path
    }

    /// A checkout of main, as an agent would get it.
    pub fn clone(&self, name: &str) -> PathBuf {
        let path = self.checkout(name);
        self.ok("github_fetch", json!({"workspace": path}));
        git(&path, &["checkout", "-q", "-b", "daniel/x", "origin/main"]);
        path
    }

    pub fn commit(&self, dir: &Path, text: &str) -> String {
        std::fs::write(dir.join("file"), format!("{text}\n")).unwrap();
        git(dir, &["add", "file"]);
        git(dir, &["commit", "-q", "-m", text]);
        git(dir, &["rev-parse", "HEAD"])
    }

    pub fn hub_ref(&self, repo: &str, branch: &str) -> Option<String> {
        let out = git(
            &self.hub(repo),
            &["for-each-ref", "--format=%(objectname)", &format!("refs/heads/{branch}")],
        );
        Some(out).filter(|o| !o.is_empty())
    }

    /// Calls a tool through the shim: (text, is_error).
    pub fn tool(&self, name: &str, args: Value) -> (String, bool) {
        let line = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": name, "arguments": args}});
        let mut out = Vec::new();
        Shim::new(self.socket()).run(format!("{line}\n").as_bytes(), &mut out).unwrap();
        let reply: Value = serde_json::from_slice(&out).unwrap();
        let result = &reply["result"];
        (result["content"][0]["text"].as_str().unwrap().into(), result["isError"].as_bool().unwrap())
    }

    pub fn ok(&self, name: &str, args: Value) -> String {
        let (text, is_error) = self.tool(name, args);
        assert!(!is_error, "{name}: {text}");
        text
    }

    pub fn err(&self, name: &str, args: Value) -> String {
        let (text, is_error) = self.tool(name, args);
        assert!(is_error, "{name} should have failed: {text}");
        text
    }

    pub fn push(&self, dir: &Path, force: bool) -> (String, bool) {
        self.tool("github_push", json!({"workspace": dir, "branch": "daniel/x", "force": force}))
    }

    /// Nothing of a push may stay behind.
    pub fn assert_clean(&self) {
        assert_eq!(git(&self.mirror(), &["for-each-ref", "refs/staging"]), "");
        assert_eq!(std::fs::read_dir(self.dir.path().join("data/tmp")).unwrap().count(), 0);
    }
}

/// Speaks the socket protocol directly, as a rogue agent would.
pub struct Raw(BufReader<UnixStream>);

impl Raw {
    pub fn connect(world: &World) -> Raw {
        Raw(BufReader::new(UnixStream::connect(world.socket()).unwrap()))
    }

    pub fn send(&mut self, op: &str, args: Value, blob: Option<&[u8]>) -> Value {
        let mut m = json!({"id": 1, "op": op, "args": args});
        if let Some(blob) = blob {
            m["blob_len"] = json!(blob.len());
        }
        self.write(format!("{m}\n").as_bytes());
        if let Some(blob) = blob {
            self.write(blob);
        }
        self.read()
    }

    pub fn write(&mut self, bytes: &[u8]) {
        let _ = self.0.get_mut().write_all(bytes);
    }

    pub fn read(&mut self) -> Value {
        let mut line = String::new();
        self.0.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap_or(Value::Null)
    }

    pub fn error(&mut self, op: &str, args: Value, blob: Option<&[u8]>) -> String {
        let r = self.send(op, args, blob);
        assert_eq!(r["ok"], false, "{r}");
        r["error"].as_str().unwrap().into()
    }
}

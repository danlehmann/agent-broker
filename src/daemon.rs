//! The daemon: startup checks and the agent socket.

use std::collections::HashMap;
use std::fs::{DirBuilder, File, Permissions};
use std::io::{BufReader, ErrorKind, Seek, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::db::Db;
use crate::dispatch::{Broker, Pending, Reply, log};
use crate::error::{Error, Result, refuse};
use crate::github::{Endpoints, GitHub};
use crate::platform::{self, Kernel};
use crate::proto;

const IDLE: Duration = Duration::from_secs(120);
const MAX_CONNECTIONS: usize = 256;
const MAX_PER_UID: usize = 16;

pub struct Options {
    pub data_dir: PathBuf,
    pub run_dir: PathBuf,
}

type Fatal = std::result::Result<(), String>;

pub fn check_not_root() -> Fatal {
    if platform::own_uid() == 0 { Err("refusing to run as root".into()) } else { Ok(()) }
}

/// The data dir must be a real directory, ours, and closed to everyone else.
pub fn check_data_dir(dir: &Path) -> Fatal {
    let shown = dir.display();
    let meta = std::fs::symlink_metadata(dir).map_err(|e| format!("data dir {shown}: {e}"))?;
    if !meta.is_dir() {
        return Err(format!("data dir {shown} is not a directory"));
    }
    if meta.uid() != platform::own_uid() {
        return Err(format!("data dir {shown} belongs to another account"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!("data dir {shown} is accessible to others; run chmod 700 on it"));
    }
    Ok(())
}

/// The run dir must be ours and writable by nobody else, or others could replace the sockets.
pub fn check_run_dir(dir: &Path) -> Fatal {
    let shown = dir.display();
    if !dir.exists() {
        std::fs::create_dir(dir).map_err(|e| format!("run dir {shown}: {e}"))?;
        std::fs::set_permissions(dir, Permissions::from_mode(0o755))
            .map_err(|e| format!("run dir {shown}: {e}"))?;
    }
    let meta = std::fs::symlink_metadata(dir).map_err(|e| format!("run dir {shown}: {e}"))?;
    if !meta.is_dir() || meta.uid() != platform::own_uid() {
        return Err(format!("run dir {shown} must be a directory owned by the broker account"));
    }
    if meta.mode() & 0o022 != 0 || meta.mode() & 0o011 != 0o011 {
        return Err(format!("run dir {shown} must have mode 755 or 711"));
    }
    Ok(())
}

pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

/// Binds a socket that every local account may connect to: identity is checked per
/// connection, not by file permissions.
fn bind(path: &Path) -> std::io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => return Err(std::io::Error::other("exists and is not a socket")),
        Err(_) => {}
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, Permissions::from_mode(0o666))?;
    Ok(listener)
}

pub fn run(options: &Options) -> Fatal {
    check_not_root()?;
    check_data_dir(&options.data_dir)?;
    check_run_dir(&options.run_dir)?;
    let lock_path = options.data_dir.join("lock");
    let lock = File::create(&lock_path).map_err(|e| format!("{}: {e}", lock_path.display()))?;
    lock.try_lock().map_err(|_| "another daemon is using this data dir".to_string())?;

    let tmp = options.data_dir.join("tmp");
    let _ = std::fs::remove_dir_all(&tmp); // leftovers of a crash
    create_private_dir(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    let home = platform::own_home().ok_or("the broker account has no home directory")?;
    let db = Db::open(&options.data_dir.join("broker.db")).map_err(|e| e.to_string())?;
    let github = GitHub::new(Endpoints::github(), &options.data_dir, home);
    let broker = Arc::new(Broker::new(db, github, Box::new(Kernel), platform::own_uid()));

    let socket = options.run_dir.join("agent.sock");
    let listener = bind(&socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    log(&format!("listening on {}", socket.display()), None);
    serve(&broker, &listener);
    Ok(())
}

/// Accepts connections until the listener fails for good.
pub fn serve(broker: &Arc<Broker>, listener: &UnixListener) {
    let counts: Arc<Mutex<HashMap<u32, usize>>> = Arc::default();
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                log(&format!("accept: {e}"), None);
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let Ok(uid) = broker.identity.peer_uid(&stream) else { continue };
        let Some(slot) = Slot::take(&counts, uid) else {
            let _ = stream.set_nonblocking(true);
            let _ = proto::write_message(&mut &stream, &failure(&Value::Null, "too many connections"));
            continue;
        };
        let broker = broker.clone();
        let spawned = std::thread::Builder::new().spawn(move || {
            let _slot = slot;
            // Errors here are the peer's doing: it hung up or broke the protocol.
            let _ = connection(&broker, &stream, uid);
        });
        if let Err(e) = spawned {
            log(&format!("cannot start a thread: {e}"), None);
        }
    }
}

/// A uid's share of the connections, so that one account cannot use them all up.
struct Slot {
    counts: Arc<Mutex<HashMap<u32, usize>>>,
    uid: u32,
}

impl Slot {
    fn take(counts: &Arc<Mutex<HashMap<u32, usize>>>, uid: u32) -> Option<Slot> {
        let mut map = counts.lock().unwrap_or_else(|e| e.into_inner());
        if map.values().sum::<usize>() >= MAX_CONNECTIONS {
            return None;
        }
        let n = map.entry(uid).or_insert(0);
        if *n >= MAX_PER_UID {
            return None;
        }
        *n += 1;
        Some(Slot { counts: counts.clone(), uid })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut map = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = map.get_mut(&self.uid) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.uid);
            }
        }
    }
}

fn failure(id: &Value, message: &str) -> Value {
    json!({"id": id, "ok": false, "error": message})
}

fn connection(broker: &Broker, stream: &UnixStream, uid: u32) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IDLE))?;
    stream.set_write_timeout(Some(IDLE))?;
    let mut session = Session { broker, uid, pending: None };
    let mut reader = BufReader::new(stream);
    loop {
        let request = match proto::read_message(&mut reader) {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(e) => {
                let timed_out = matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut);
                if timed_out && let Some(pending) = session.pending.take() {
                    // The caller is still packing. It reads this when it comes back.
                    let late = "the upload took too long to start; try again";
                    broker.abandon(uid, &pending, late);
                    let mut stream = stream;
                    let _ = proto::write_message(&mut stream, &failure(&Value::Null, late));
                }
                return Err(e);
            }
        };
        // Also for the bytes of an upload: once it has started, it has to keep coming.
        stream.set_read_timeout(Some(IDLE))?;
        session.request(&mut reader, stream, &request)?;
        stream.set_read_timeout(Some(session.wait()))?;
    }
    Ok(())
}

struct Session<'a> {
    broker: &'a Broker,
    uid: u32,
    pending: Option<Pending>,
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.broker.abandon(self.uid, &pending, "the caller disconnected");
        }
    }
}

impl Session<'_> {
    /// How long to wait for the next request.
    fn wait(&self) -> Duration {
        match &self.pending {
            // Between the two steps of an upload the caller is busy packing, not idle. It
            // gets the time that is left for the upload, never more than that.
            Some(pending) => pending.remaining().max(Duration::from_secs(1)),
            None => IDLE,
        }
    }

    fn request(
        &mut self,
        reader: &mut BufReader<&UnixStream>,
        mut stream: &UnixStream,
        request: &Map<String, Value>,
    ) -> std::io::Result<()> {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let op = request.get("op").and_then(Value::as_str).unwrap_or_default();
        let empty = Map::new();
        let args = request.get("args").and_then(Value::as_object).unwrap_or(&empty);

        let blob = match proto::blob_len(request)? {
            None => None,
            Some(len) => match self.receive(reader, op, args, len) {
                Ok(file) => Some(file),
                Err(e) => {
                    if let Error::Internal(m) = &e {
                        log(&format!("{op}: storing the upload: {m}"), None);
                    }
                    if let Some(pending) = self.pending.take() {
                        self.broker.abandon(self.uid, &pending, e.public());
                    }
                    // The bytes are still in the pipe, so the connection cannot go on.
                    proto::write_message(&mut stream, &failure(&id, e.public()))?;
                    return Err(std::io::Error::other("blob refused"));
                }
            },
        };
        let result = self.run(op, args, blob.as_ref().map(|f| f.path()));
        match result {
            Ok(Reply { value, blob: None }) => {
                proto::write_message(&mut stream, &json!({"id": id, "ok": true, "result": value}))
            }
            Ok(Reply { value, blob: Some(file) }) => {
                let mut file = File::open(file.path())?;
                let len = file.seek(std::io::SeekFrom::End(0))?;
                file.rewind()?;
                let reply = json!({"id": id, "ok": true, "result": value, "blob_len": len});
                proto::write_message(&mut stream, &reply)?;
                proto::copy_exact(&mut file, &mut stream, len)
            }
            Err(e) => {
                if let Error::Internal(m) = &e {
                    log(&format!("{op}: {m}"), None);
                }
                proto::write_message(&mut stream, &failure(&id, e.public()))
            }
        }
    }

    /// Stores an announced blob, if one is expected.
    fn receive(
        &self,
        reader: &mut BufReader<&UnixStream>,
        op: &str,
        args: &Map<String, Value>,
        len: u64,
    ) -> Result<tempfile::NamedTempFile> {
        if op != "tools.finish" || !self.is_pending(args) {
            return refuse("no upload was expected");
        }
        // Before reading it: a late upload may be large.
        if self.pending.as_ref().is_some_and(Pending::expired) {
            return refuse("the upload took too long to start; try again");
        }
        if len > self.broker.db.max_blob()? {
            return refuse("the upload is larger than the broker's limit; ask the human to raise it");
        }
        let mut file = tempfile::NamedTempFile::new_in(self.broker.github.tmp())?;
        proto::copy_exact(reader, &mut file, len)?;
        file.flush()?;
        Ok(file)
    }

    fn is_pending(&self, args: &Map<String, Value>) -> bool {
        let id = args.get("call_id").and_then(Value::as_str);
        id.is_some() && self.pending.as_ref().map(|p| p.call_id.as_str()) == id
    }

    fn run(&mut self, op: &str, args: &Map<String, Value>, blob: Option<&Path>) -> Result<Reply> {
        let (broker, uid) = (self.broker, self.uid);
        match op {
            "whoami" => broker.whoami(uid),
            "link" => broker.link(uid, args),
            "tools.list" => broker.tools_list(uid),
            "tools.call" => broker.call(uid, args),
            "tools.begin" => {
                if let Some(old) = self.pending.take() {
                    broker.abandon(uid, &old, "the caller started another call");
                }
                let (reply, pending) = broker.begin(uid, args)?;
                self.pending = pending;
                Ok(reply)
            }
            "tools.finish" if self.is_pending(args) => match self.pending.take() {
                Some(pending) => broker.finish(uid, pending, blob),
                None => refuse("no such call"),
            },
            "tools.finish" => refuse("no such call"),
            _ => refuse("unknown operation"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_checks() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("d");
        let set = |mode| std::fs::set_permissions(&dir, Permissions::from_mode(mode)).unwrap();
        assert!(check_data_dir(&dir).is_err());
        std::fs::create_dir(&dir).unwrap();
        for (mode, data, run) in [
            (0o700, true, false),
            (0o711, false, true),
            (0o755, false, true),
            (0o750, false, false),
            (0o775, false, false),
            (0o757, false, false),
        ] {
            set(mode);
            assert_eq!(check_data_dir(&dir).is_ok(), data, "data {mode:o}");
            assert_eq!(check_run_dir(&dir).is_ok(), run, "run {mode:o}");
        }
        set(0o700);
        let link = base.path().join("l");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(check_data_dir(&link).is_err());
        assert!(check_run_dir(&link).is_err());
        assert!(check_data_dir(Path::new("/")).is_err());
    }

    #[test]
    fn connection_slots() {
        let counts = Arc::default();
        let slots: Vec<_> = (0..MAX_PER_UID).map(|_| Slot::take(&counts, 1).unwrap()).collect();
        assert!(Slot::take(&counts, 1).is_none());
        assert!(Slot::take(&counts, 2).is_some());
        drop(slots);
        assert!(counts.lock().unwrap().is_empty());
    }
}

//! The MCP server the agent harness launches, and the client side of the agent socket.
//!
//! Runs as the agent. Nothing here is a security boundary.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::error::{Error, Result, refuse};
use crate::github::local::{Checkout, checkout};
use crate::proto;
use crate::spec::{self, Args, Flow, str_arg};

/// Newest first.
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// A connection to the daemon.
pub struct Client {
    reader: BufReader<UnixStream>,
    next_id: u64,
}

fn lost(e: io::Error) -> Error {
    Error::Refused(format!("lost the connection to the agent-broker daemon: {e}"))
}

impl Client {
    pub fn connect(socket: &Path) -> Result<Client> {
        match UnixStream::connect(socket) {
            Ok(stream) => Ok(Client { reader: BufReader::new(stream), next_id: 1 }),
            Err(e) => refuse(format!(
                "cannot reach the agent-broker daemon at {}: {e}. If the harness runs in a sandbox, allow this socket; otherwise ask the human whether the daemon runs",
                socket.display()
            )),
        }
    }

    pub fn call(&mut self, op: &str, args: Value) -> Result<Value> {
        self.exchange(op, args, None).map(|r| r.0)
    }

    /// Sends a request, with a blob if given, and receives the reply, with its blob if any.
    fn exchange(
        &mut self,
        op: &str,
        args: Value,
        blob: Option<&Path>,
    ) -> Result<(Value, Option<tempfile::NamedTempFile>)> {
        let id = self.next_id;
        self.next_id += 1;
        let mut request = json!({"id": id, "op": op, "args": args});
        // What can fail before anything is sent fails here, without waiting for a reply.
        let mut blob = match blob {
            None => None,
            Some(path) => {
                let file = File::open(path)?;
                let len = file.metadata()?.len();
                request["blob_len"] = json!(len);
                Some((file, len))
            }
        };
        let Ok(line) = proto::encode(&request) else {
            return refuse(
                "the request is larger than agent-broker accepts (1 MiB); make its arguments shorter",
            );
        };
        let sent = (|| {
            let mut stream = self.reader.get_ref();
            stream.write_all(&line)?;
            stream.flush()?;
            match &mut blob {
                None => Ok(()),
                Some((file, len)) => proto::copy_exact(file, &mut stream, *len),
            }
        })();
        // Even if sending failed there may be a reply: the daemon refuses large blobs early.
        let reply = match (proto::read_message(&mut self.reader), sent) {
            (Ok(Some(reply)), _) => reply,
            (_, Err(e)) | (Err(e), _) => return Err(lost(e)),
            (Ok(None), Ok(())) => return Err(lost(io::ErrorKind::UnexpectedEof.into())),
        };
        if reply.get("ok") != Some(&Value::Bool(true)) {
            let message = reply.get("error").and_then(Value::as_str).unwrap_or("no reason given");
            return refuse(message);
        }
        let blob = match proto::blob_len(&reply).map_err(lost)? {
            None => None,
            Some(len) => {
                let mut file = tempfile::NamedTempFile::new()?;
                proto::copy_exact(&mut self.reader, &mut file, len).map_err(lost)?;
                Some(file)
            }
        };
        Ok((reply.get("result").cloned().unwrap_or(Value::Null), blob))
    }
}

pub struct Shim {
    socket: PathBuf,
}

impl Shim {
    pub fn new(socket: PathBuf) -> Shim {
        Shim { socket }
    }

    /// Serves MCP until the input ends.
    pub fn run(&self, input: impl BufRead, mut output: impl Write) -> io::Result<()> {
        for line in input.split(b'\n') {
            let Ok(Value::Object(message)) = serde_json::from_slice(&line?) else { continue };
            if let Some(reply) = self.handle(&message) {
                let mut line = serde_json::to_vec(&reply)?;
                line.push(b'\n');
                output.write_all(&line)?;
                output.flush()?;
            }
        }
        Ok(())
    }

    fn handle(&self, message: &Map<String, Value>) -> Option<Value> {
        let id = message.get("id")?;
        let method = message.get("method")?.as_str()?;
        let empty = Map::new();
        let params = message.get("params").and_then(Value::as_object).unwrap_or(&empty);
        let result = match method {
            "initialize" => Ok(initialize(params)),
            "ping" => Ok(json!({})),
            "tools/list" => Client::connect(&self.socket)
                .and_then(|mut c| c.call("tools.list", json!({})))
                .map_err(|e| (-32000, e.public().to_string())),
            "tools/call" => Ok(self.tools_call(params)),
            _ => Err((-32601, format!("unknown method {method}"))),
        };
        Some(match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, message)) => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
            }
        })
    }

    fn tools_call(&self, params: &Args) -> Value {
        let (text, is_error) = match self.run_tool(params) {
            Ok(text) => (text, false),
            Err(Error::Refused(m)) => (m, true),
            Err(Error::Internal(m)) => (m, true), // our own side, so nothing to hide
        };
        json!({"content": [{"type": "text", "text": text}], "isError": is_error})
    }

    fn run_tool(&self, params: &Args) -> Result<String> {
        let empty = Map::new();
        let args = match params.get("arguments") {
            None => Some(&empty),
            Some(v) => v.as_object(),
        };
        let tool = params.get("name").and_then(Value::as_str).and_then(spec::find);
        let (Some(tool), Some(args)) = (tool, args) else { return refuse("unknown tool") };
        // The daemon checks again; this is for the local half, which comes first.
        if tool.flow != Flow::Plain {
            tool.validate(args)?;
        }
        let mut client = Client::connect(&self.socket)?;
        let request = json!({"name": tool.name, "arguments": args});
        match tool.flow {
            Flow::Plain => Ok(reply_text(&client.call("tools.call", request)?)),
            Flow::Download => download(&mut client, &checkout(args)?, args, request),
            Flow::Upload => upload(&mut client, &checkout(args)?, args, request),
        }
    }
}

fn initialize(params: &Args) -> Value {
    let asked = str_arg(params, "protocolVersion");
    let version = PROTOCOL_VERSIONS.iter().find(|v| Some(**v) == asked).unwrap_or(&PROTOCOL_VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "agent-broker", "version": env!("CARGO_PKG_VERSION")},
    })
}

fn reply_text(reply: &Value) -> String {
    reply["text"].as_str().unwrap_or_default().to_string()
}

fn download(client: &mut Client, checkout: &Checkout, args: &Args, mut request: Value) -> Result<String> {
    request["local"] = json!({"haves": checkout.haves(args)?});
    let (reply, blob) = client.exchange("tools.call", request, None)?;
    let empty = Map::new();
    let local = reply["local"].as_object().unwrap_or(&empty);
    checkout.store(local, blob.as_ref().map(|f| f.path()))
}

fn upload(client: &mut Client, checkout: &Checkout, args: &Args, mut request: Value) -> Result<String> {
    let branch = str_arg(args, "branch").unwrap_or_default();
    request["local"] = Value::Object(checkout.push_facts(args)?);
    let mut reply = client.call("tools.begin", request)?;
    if let Some(call_id) = reply["call_id"].as_str() {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("bundle");
        let blob = if reply["need_blob"] == true {
            let basis: Vec<String> = reply["basis"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|b| b.as_str().map(Into::into))
                .collect();
            checkout.bundle(branch, &basis, &file)?;
            Some(file.as_path())
        } else {
            None
        };
        let args = json!({"call_id": call_id});
        reply = client.exchange("tools.finish", args, blob)?.0;
    }
    let mut text = reply_text(&reply);
    let tip = reply["local"]["tip"].as_str().unwrap_or_default();
    if let Err(e) = checkout.pushed(branch, tip) {
        text.push_str(&format!("\nnote: {}", e.public()));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn talk(input: &str) -> Vec<Value> {
        let mut out = Vec::new();
        Shim::new("/nonexistent/agent.sock".into()).run(input.as_bytes(), &mut out).unwrap();
        String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    #[test]
    fn protocol() {
        let out = talk(
            "garbage\n[1]\n{\"method\":\"notifications/initialized\"}\n{\"id\":9}\n\
             {\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\"}}\n\
             {\"id\":2,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"1999-01-01\"}}\n\
             {\"id\":\"p\",\"method\":\"ping\",\"params\":7}\n\
             {\"id\":3,\"method\":\"nope\"}\n",
        );
        assert_eq!(out.len(), 4);
        assert_eq!(out[0]["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(out[0]["result"]["serverInfo"]["name"], "agent-broker");
        assert_eq!(out[1]["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
        assert_eq!(out[2], json!({"jsonrpc": "2.0", "id": "p", "result": {}}));
        assert_eq!(out[3]["error"], json!({"code": -32601, "message": "unknown method nope"}));
    }

    #[test]
    fn unknown_tools_and_missing_daemon() {
        for params in [
            json!({}),
            json!({"name": 1}),
            json!({"name": "x"}),
            json!({"name": "github_repos", "arguments": []}),
        ] {
            let out = talk(&format!("{}\n", json!({"id": 1, "method": "tools/call", "params": params})));
            assert_eq!(out[0]["result"]["content"][0]["text"], "unknown tool");
            assert_eq!(out[0]["result"]["isError"], true);
        }
        let out = talk("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"github_repos\"}}\n");
        assert_eq!(out[0]["result"]["isError"], true);
        assert!(out[0]["result"]["content"][0]["text"].as_str().unwrap().contains("cannot reach"));
    }
}

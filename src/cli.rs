//! Command line.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::json;

use crate::daemon;
use crate::db::{AuditEntry, Db};
use crate::platform;
use crate::shim::{Client, Shim};

const USAGE: &str = "usage:
  agent-broker daemon [--data-dir DIR] [--run-dir DIR]
  agent-broker mcp [--run-dir DIR]
  agent-broker link [--run-dir DIR]
  agent-broker reset-login USERNAME [--data-dir DIR] [--run-dir DIR]
";

type Outcome = Result<(), String>;

/// `--name value` options; anything else is an error.
pub struct Flags(Vec<(String, String)>);

impl Flags {
    fn parse(args: &[String], known: &[&str]) -> Result<Flags, String> {
        let mut flags = Vec::new();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let name = arg.strip_prefix("--").filter(|n| known.contains(n));
            match (name, args.next()) {
                (Some(name), Some(value)) => flags.push((name.to_string(), value.clone())),
                (Some(_), None) => return Err(format!("{arg} needs a value")),
                (None, _) => return Err(format!("unknown argument {arg}\n{USAGE}")),
            }
        }
        Ok(Flags(flags))
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().rev().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    pub fn need(&self, name: &str) -> Result<&str, String> {
        self.get(name).ok_or_else(|| format!("--{name} is required"))
    }

    pub fn data_dir(&self) -> Result<PathBuf, String> {
        match self.get("data-dir") {
            Some(dir) => Ok(dir.into()),
            None => Ok(platform::own_home().ok_or("this account has no home directory")?.join("data")),
        }
    }

    fn run_dir(&self) -> PathBuf {
        self.get("run-dir").unwrap_or(platform::DEFAULT_RUN_DIR).into()
    }
}

pub fn main() -> ExitCode {
    let args: Vec<String> = match std::env::args_os().skip(1).map(|a| a.into_string()).collect() {
        Ok(args) => args,
        Err(_) => {
            eprintln!("arguments must be UTF-8");
            return ExitCode::FAILURE;
        }
    };
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("agent-broker: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String]) -> Outcome {
    let (command, rest) = match args.split_first() {
        Some((c, rest)) => (c.as_str(), rest),
        None => return Err(USAGE.into()),
    };
    match command {
        "daemon" => {
            let flags = Flags::parse(rest, &["data-dir", "run-dir"])?;
            let options = daemon::Options { data_dir: flags.data_dir()?, run_dir: flags.run_dir() };
            close_off();
            daemon::run(&options)
        }
        "mcp" => {
            let flags = Flags::parse(rest, &["run-dir"])?;
            Shim::new(flags.run_dir().join("agent.sock"))
                .run(std::io::stdin().lock(), std::io::stdout().lock())
                .map_err(|e| e.to_string())
        }
        "link" => {
            let flags = Flags::parse(rest, &["run-dir"])?;
            link(&flags.run_dir().join("agent.sock"))
        }
        "reset-login" => {
            let (username, rest) = rest.split_first().ok_or(USAGE)?;
            let flags = Flags::parse(rest, &["data-dir", "run-dir"])?;
            close_off();
            reset_login(&flags, username)
        }
        _ => Err(USAGE.into()),
    }
}

/// Files we create are private, and nothing is inherited from whoever started us.
fn close_off() {
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    for (name, _) in std::env::vars_os().collect::<Vec<_>>() {
        // SAFETY: called from `main` before any other thread exists.
        unsafe { std::env::remove_var(name) };
    }
}

/// Makes a one-time link to set a user's password. Run by the human through sudo, which is
/// what makes it the way back in.
fn reset_login(flags: &Flags, username: &str) -> Outcome {
    daemon::check_not_root()?;
    let data = flags.data_dir()?;
    daemon::check_data_dir(&data)?;
    let db = Db::open(&data.join("broker.db")).map_err(|e| e.to_string())?;
    let fail = |e: crate::error::Error| e.to_string();
    let user = db.user_id(username).map_err(fail)?.ok_or("no such user")?;
    let token = db.new_one_time_link(user, "reset").map_err(fail)?;
    let entry = AuditEntry {
        event: "reset link made",
        uid: Some(nix::unistd::getuid().as_raw()),
        username: Some(username),
        ok: Some(true),
        detail: "on the command line",
        ..Default::default()
    };
    db.audit(&entry).map_err(fail)?;
    println!(
        "{}\nOpen this link within 15 minutes and set the password. It works once:\n\n    \
         http://localhost:8443/setup/{token}\n",
        daemon::how_to_reach(&flags.run_dir().join("admin.sock"))
    );
    Ok(())
}

/// Claims a link code. The code is read from stdin because arguments are visible to others.
fn link(socket: &std::path::Path) -> Outcome {
    let mut client = Client::connect(socket).map_err(|e| e.public().to_string())?;
    print!("link code: ");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut code = String::new();
    std::io::stdin().lock().read_line(&mut code).map_err(|e| e.to_string())?;
    let reply = client.call("link", json!({"code": code.trim()})).map_err(|e| e.public().to_string())?;
    println!("{}", reply["text"].as_str().unwrap_or("claimed"));
    Ok(())
}

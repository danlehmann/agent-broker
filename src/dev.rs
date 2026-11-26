//! Seeds the database until the web UI exists. Not part of normal builds; remove with the UI.

use std::io::BufRead;

use crate::cli::Flags;
use crate::daemon::{check_data_dir, check_not_root, create_private_dir};
use crate::db::Db;
use crate::github::{Endpoints, GitHub, TOOLS, rules};
use crate::platform;

pub fn run(what: &str, flags: &Flags) -> Result<(), String> {
    check_not_root()?;
    let data = flags.data_dir()?;
    create_private_dir(&data).map_err(|e| e.to_string())?;
    check_data_dir(&data)?;
    let db = Db::open(&data.join("broker.db")).map_err(|e| e.to_string())?;
    seed(&db, &data, what, flags).map_err(|e| e.to_string())
}

fn seed(
    db: &Db,
    data: &std::path::Path,
    what: &str,
    flags: &Flags,
) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(what, "add-user" | "add-repo" | "link-code" | "confirm") {
        return Err("dev: add-user, add-repo, link-code or confirm".into());
    }
    let name = flags.need("user")?;
    if what == "add-user" {
        db.add_user(name, true)?;
        println!("added user {name}");
        return Ok(());
    }
    let user = db.user_id(name)?.ok_or("no such user")?;
    match what {
        "add-repo" => {
            let repo = flags.need("repo")?;
            rules::check_repo_name(repo)?;
            let prefix = flags.need("prefix")?;
            rules::check_branch(&format!("{prefix}x"), prefix)?;
            eprint!("token (on stdin): ");
            let mut token = String::new();
            std::io::stdin().lock().read_line(&mut token)?;
            let token = token.trim();
            if token.is_empty() {
                return Err("no token given".into());
            }
            let home = platform::own_home().ok_or("no home directory")?;
            let github = GitHub::new(Endpoints::github(), data, home);
            let (full_name, default_branch) = github.look_up_repo(repo, token)?;
            if default_branch.starts_with(prefix) {
                return Err(
                    format!("the prefix {prefix} would cover the default branch {default_branch}").into()
                );
            }
            let tools: Vec<&str> = TOOLS.iter().map(|t| t.name).collect();
            db.add_github_repo(user, token, &full_name, prefix, &default_branch, &tools)?;
            println!("added {full_name} (default branch {default_branch})");
        }
        "link-code" => println!("{}", db.new_link_code(user)?),
        "confirm" => {
            let account = flags.need("account")?;
            let uid = platform::uid_of_account(account).ok_or("no such account")?;
            db.confirm_link(user, uid)?;
            println!("linked {account} (uid {uid}) to {name}");
        }
        _ => return Err("dev: add-user, add-repo, link-code or confirm".into()),
    }
    Ok(())
}

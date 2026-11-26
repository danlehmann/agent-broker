//! Pull request tools.

use serde_json::{Map, Value, json};

use super::api::{Api, MAX_ITEMS, text};
use super::rules::check_own_pr;
use crate::error::{Result, refuse};
use crate::spec::{Args, int_arg, str_arg};

pub fn create(api: &Api, args: &Args) -> Result<String> {
    let pr = api.send(
        "POST",
        "/pulls",
        &json!({
            "title": str_arg(args, "title"),
            "body": str_arg(args, "body").unwrap_or(""),
            "head": str_arg(args, "branch"),
            "base": str_arg(args, "base").unwrap_or(&api.entry.default_branch),
            "draft": true,
        }),
    )?;
    Ok(format!("opened draft PR #{}: {}", pr["number"], text(&pr["html_url"])))
}

/// Loads the PR and checks that it comes from one of the caller's branches.
fn load_own(api: &Api, args: &Args) -> Result<(i64, Value)> {
    let number = int_arg(args, "number").unwrap_or(0);
    let pr = api.get(&format!("/pulls/{number}"), &[])?;
    check_own_pr(&pr, number, api.entry)?;
    Ok((number, pr))
}

/// The fields `github_pr_update` is asked to change.
pub fn changes(args: &Args) -> Result<Map<String, Value>> {
    if let Some(state) = str_arg(args, "state")
        && !matches!(state, "open" | "closed")
    {
        return refuse("state must be 'open' or 'closed'");
    }
    let change: Map<String, Value> = ["title", "body", "state"]
        .iter()
        .filter_map(|n| Some((n.to_string(), args.get(*n)?.clone())))
        .collect();
    if change.is_empty() {
        return refuse("nothing to change");
    }
    Ok(change)
}

pub fn update(api: &Api, args: &Args) -> Result<String> {
    let change = changes(args)?;
    let (number, _) = load_own(api, args)?;
    let names: Vec<&str> =
        ["title", "body", "state"].into_iter().filter(|n| change.contains_key(*n)).collect();
    let names = names.join(", ");
    api.send("PATCH", &format!("/pulls/{number}"), &Value::Object(change))?;
    Ok(format!("updated PR #{number} ({names})"))
}

/// Where `github_pr_comment` puts the comment.
pub enum Place<'a> {
    Conversation,
    Reply(i64),
    Line(&'a str, i64),
}

pub fn place(args: &Args) -> Result<Place<'_>> {
    match (int_arg(args, "reply_to"), str_arg(args, "path"), int_arg(args, "line")) {
        (None, None, None) => Ok(Place::Conversation),
        (Some(id), None, None) => Ok(Place::Reply(id)),
        (None, Some(path), Some(line)) if !path.is_empty() => Ok(Place::Line(path, line)),
        (None, _, _) => refuse("an inline comment needs both path and line"),
        (Some(_), _, _) => refuse("give either reply_to or path and line, not both"),
    }
}

/// First line of every comment, because GitHub shows the human as its author.
pub const AGENT_MARK: &str = "[Written by an agent]";

fn marked(body: &str) -> String {
    match body.trim_start().starts_with(AGENT_MARK) {
        true => body.to_string(),
        false => format!("{AGENT_MARK}\n\n{body}"),
    }
}

pub fn comment(api: &Api, args: &Args) -> Result<String> {
    let place = place(args)?;
    let (number, pr) = load_own(api, args)?;
    let body = marked(str_arg(args, "body").unwrap_or_default());
    let reply = match place {
        Place::Conversation => {
            api.send("POST", &format!("/issues/{number}/comments"), &json!({"body": body}))?
        }
        Place::Reply(id) => {
            let target = api.get(&format!("/pulls/comments/{id}"), &[])?;
            if !text(&target["pull_request_url"]).ends_with(&format!("/pulls/{number}")) {
                return refuse(format!("review comment {id} is not on PR #{number}"));
            }
            // GitHub takes replies only to the comment that started a thread.
            let first = target["in_reply_to_id"].as_i64().unwrap_or(id);
            api.send("POST", &format!("/pulls/{number}/comments/{first}/replies"), &json!({"body": body}))?
        }
        Place::Line(path, line) => api.send(
            "POST",
            &format!("/pulls/{number}/comments"),
            &json!({"body": body, "commit_id": text(&pr["head"]["sha"]), "path": path,
                    "line": line, "side": "RIGHT"}),
        )?,
    };
    Ok(format!("commented: {}", text(&reply["html_url"])))
}

pub fn list_state(args: &Args) -> Result<&str> {
    match str_arg(args, "state").unwrap_or("open") {
        s @ ("open" | "closed" | "all") => Ok(s),
        _ => refuse("state must be 'open', 'closed' or 'all'"),
    }
}

pub fn list(api: &Api, args: &Args) -> Result<String> {
    let state = list_state(args)?;
    let prefix = &api.entry.branch_prefix;
    let found = api.paged("/pulls", &[("state", state)], None)?;
    let mut lines: Vec<String> = found
        .items
        .iter()
        .filter(|pr| text(&pr["head"]["ref"]).starts_with(prefix.as_str()))
        .map(|pr| {
            let draft = pr["draft"].as_bool() == Some(true);
            let shown = if draft { "draft" } else { text(&pr["state"]) };
            format!("#{} [{shown}] {}: {}", pr["number"], text(&pr["head"]["ref"]), text(&pr["title"]))
        })
        .collect();
    // "open PRs", "closed PRs", or just "PRs" for all of them.
    let kind = if state == "all" { "PRs".to_string() } else { format!("{state} PRs") };
    if lines.is_empty() {
        lines.push(format!("no {kind} from {prefix}* branches"));
    }
    if found.cut {
        lines.push(format!(
            "(only the {MAX_ITEMS} newest {kind} of the repo were searched; older ones are missing here)"
        ));
    }
    Ok(lines.join("\n"))
}

pub fn view(api: &Api, args: &Args) -> Result<String> {
    let number = match (int_arg(args, "number"), str_arg(args, "branch")) {
        (Some(number), _) => number,
        (None, Some(branch)) => {
            let head = format!("{}:{branch}", api.entry.owner());
            let found = api.get("/pulls", &[("head", &head), ("state", "all")])?;
            match found[0]["number"].as_i64() {
                Some(number) => number,
                None => return refuse(format!("no PR for branch {branch}")),
            }
        }
        (None, None) => return refuse("give number or branch"),
    };
    let pr = api.get(&format!("/pulls/{number}"), &[])?;
    let flag = |name: &str, shown: &'static str| if pr[name] == true { shown } else { "" };
    let mut out = format!(
        "#{number} {}\nstate: {}{}{}, mergeable: {}\nhead: {} @ {}, base: {}\nurl: {}\n\n{}",
        text(&pr["title"]),
        text(&pr["state"]),
        flag("draft", " (draft)"),
        flag("merged", " (merged)"),
        text(&pr["mergeable_state"]),
        text(&pr["head"]["ref"]),
        text(&pr["head"]["sha"]),
        text(&pr["base"]["ref"]),
        text(&pr["html_url"]),
        Some(text(&pr["body"])).filter(|b| !b.is_empty()).unwrap_or("(no description)"),
    );
    let mut section = |heading: &str, path: String, item: &dyn Fn(&Value) -> String| -> Result<()> {
        let found = api.paged(&path, &[], None)?;
        if !found.items.is_empty() {
            let lines: Vec<String> = found.items.iter().map(item).collect();
            out.push_str(&format!("\n\n## {heading}\n{}", lines.join("\n")));
        }
        if found.cut {
            out.push_str(&format!("\n(only the first {MAX_ITEMS} are shown; there are more)"));
        }
        Ok(())
    };
    section("Reviews", format!("/pulls/{number}/reviews"), &|r| {
        format!("- {}: {} {}", text(&r["user"]["login"]), text(&r["state"]), text(&r["body"]))
            .trim_end()
            .to_string()
    })?;
    section("Review comments", format!("/pulls/{number}/comments"), &|c| {
        let line = if c["line"].is_null() { &c["original_line"] } else { &c["line"] };
        let line = line.as_i64().map_or("?".to_string(), |l| l.to_string());
        let reply = c["in_reply_to_id"].as_i64().map_or(String::new(), |id| format!(" (reply to {id})"));
        format!(
            "- [{}]{reply} {} on {}:{line}:\n{}",
            c["id"],
            text(&c["user"]["login"]),
            text(&c["path"]),
            text(&c["body"])
        )
    })?;
    section("Comments", format!("/issues/{number}/comments"), &|c| {
        format!("- {}:\n{}", text(&c["user"]["login"]), text(&c["body"]))
    })?;
    Ok(out)
}

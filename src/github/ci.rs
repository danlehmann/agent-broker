//! GitHub Actions tools.

use regex::{Regex, RegexBuilder};

use super::api::{Api, text};
use crate::error::{Result, refuse};
use crate::spec::{Args, int_arg, str_arg};

pub fn status(api: &Api, args: &Args) -> Result<String> {
    let sha = match int_arg(args, "pr") {
        Some(pr) => text(&api.get(&format!("/pulls/{pr}"), &[])?["head"]["sha"]).to_string(),
        None => match str_arg(args, "branch").or(str_arg(args, "sha")) {
            Some(name) => text(&api.get(&format!("/commits/{name}"), &[])?["sha"]).to_string(),
            None => return refuse("give one of pr, branch, sha"),
        },
    };
    let mut out = vec![format!("commit {sha}")];
    let runs = api.paged("/actions/runs", &[("head_sha", &sha)], Some("workflow_runs"))?;
    if runs.is_empty() {
        out.push("no workflow runs for this commit (yet)".into());
    }
    for run in &runs {
        out.push(format!(
            "run {} {} ({}): {}/{} {}",
            run["id"],
            text(&run["name"]),
            text(&run["event"]),
            text(&run["status"]),
            text(&run["conclusion"]),
            text(&run["html_url"])
        ));
        let path = format!("/actions/runs/{}/jobs", run["id"]);
        let jobs = api.paged(&path, &[("filter", "latest")], Some("jobs"))?;
        let (fine, other): (Vec<_>, Vec<_>) =
            jobs.iter().partition(|j| matches!(text(&j["conclusion"]), "success" | "skipped"));
        out.push(format!("  {} of {} jobs succeeded or were skipped", fine.len(), jobs.len()));
        for job in other {
            let failed: Vec<&str> = job["steps"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|s| s["conclusion"] == "failure")
                .map(|s| text(&s["name"]))
                .collect();
            let mut line = format!(
                "  job {} {}: {}/{}",
                job["id"],
                text(&job["name"]),
                text(&job["status"]),
                text(&job["conclusion"])
            );
            if !failed.is_empty() {
                line.push_str(&format!(" (failed steps: {})", failed.join(", ")));
            }
            out.push(line);
        }
    }
    let status = api.get(&format!("/commits/{sha}/status"), &[])?;
    for s in status["statuses"].as_array().into_iter().flatten() {
        let line =
            format!("status {}: {} {}", text(&s["context"]), text(&s["state"]), text(&s["description"]));
        out.push(line.trim_end().to_string());
    }
    Ok(out.join("\n"))
}

/// The compiled `grep` argument. The engine is linear-time, so agents may supply patterns.
pub fn pattern(args: &Args) -> Result<Option<Regex>> {
    let Some(grep) = str_arg(args, "grep") else { return Ok(None) };
    match RegexBuilder::new(grep).size_limit(1 << 20).dfa_size_limit(1 << 20).build() {
        Ok(re) => Ok(Some(re)),
        Err(e) => refuse(format!("bad regex: {e}")),
    }
}

pub fn logs(api: &Api, args: &Args) -> Result<String> {
    let re = pattern(args)?;
    let log = api.log(&format!("/actions/jobs/{}/logs", int_arg(args, "job_id").unwrap_or(0)))?;
    let count = |name, default| int_arg(args, name).unwrap_or(default).max(0) as usize;
    let grep = str_arg(args, "grep").unwrap_or("");
    Ok(select(&log, re.as_ref().map(|re| (re, grep)), count("tail", 200), count("context", 3)))
}

fn select(log: &str, grep: Option<(&Regex, &str)>, tail: usize, context: usize) -> String {
    let lines: Vec<&str> = log.lines().collect();
    let total = lines.len();
    let shown: Vec<usize> = match grep {
        None => (total.saturating_sub(tail)..total).collect(),
        Some((re, _)) => {
            let mut shown = Vec::new();
            let mut next = 0; // first line not yet shown
            for (i, line) in lines.iter().enumerate() {
                if re.is_match(line) {
                    let end = i.saturating_add(context).saturating_add(1).min(total);
                    shown.extend(next.max(i.saturating_sub(context))..end.max(next));
                    next = next.max(end);
                }
            }
            shown
        }
    };
    let mut out = match grep {
        None => format!("{total} lines, last {} shown", shown.len()),
        Some((_, grep)) => format!("{total} lines, {} shown for /{grep}/", shown.len()),
    };
    for i in shown {
        out.push_str(&format!("\n{}: {}", i + 1, lines[i]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn selects_lines() {
        let log = "a\nb\nc\nd\ne\nf\n";
        assert_eq!(select(log, None, 2, 3), "6 lines, last 2 shown\n5: e\n6: f");
        assert_eq!(select(log, None, 0, 3), "6 lines, last 0 shown");
        assert_eq!(select("", None, 5, 3), "0 lines, last 0 shown");
        let re = Regex::new("[bd]").unwrap();
        assert_eq!(
            select(log, Some((&re, "[bd]")), 0, 1),
            "6 lines, 5 shown for /[bd]/\n1: a\n2: b\n3: c\n4: d\n5: e"
        );
        assert_eq!(select(log, Some((&re, "x")), 0, 0), "6 lines, 2 shown for /x/\n2: b\n4: d");
        let all = select(log, Some((&re, "x")), 0, usize::MAX);
        assert!(all.starts_with("6 lines, 6 shown"));
    }

    #[test]
    fn limits_patterns() {
        let p = |g: &str| pattern(json!({"grep": g}).as_object().unwrap());
        assert!(p("a+").unwrap().is_some());
        assert!(p("(").unwrap_err().public().starts_with("bad regex: "));
        assert!(p(r"(?=x)").is_err());
        assert!(p(r"(\w{1000}){1000}").is_err());
    }
}

//! Keeps tokens out of everything that leaves the daemon.

use std::sync::LazyLock;

use base64::{Engine, engine::general_purpose::STANDARD};
use regex::Regex;

pub const MAX_OUTPUT_CHARS: usize = 60_000;

// Services add their token formats here.
static TOKEN_FORMATS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"github_pat_\w+|gh[pousr]_\w+").expect("valid pattern"));

/// The value of an HTTP basic auth header for a token.
pub fn basic_auth(token: &str) -> String {
    STANDARD.encode(format!("x-access-token:{token}"))
}

/// Replaces the token in use, its basic-auth form and anything shaped like a token.
pub fn scrub(text: &str, token: Option<&str>) -> String {
    let mut out = text.to_string();
    if let Some(token) = token.filter(|t| !t.is_empty()) {
        out = out.replace(&basic_auth(token), "***").replace(token, "***");
    }
    TOKEN_FORMATS.replace_all(&out, "***").into_owned()
}

/// Of a longer text, how much of the start is kept. The rest of the room goes to the end.
const KEPT_START_CHARS: usize = 20_000;

/// Cuts the middle out of a text over [`MAX_OUTPUT_CHARS`] characters: the start says what
/// it is, the end of a log says what went wrong.
pub fn truncate_output(text: &str) -> String {
    let total = text.chars().count();
    if total <= MAX_OUTPUT_CHARS {
        return text.to_string();
    }
    let start: String = text.chars().take(KEPT_START_CHARS).collect();
    let end: String = text.chars().skip(total - (MAX_OUTPUT_CHARS - KEPT_START_CHARS)).collect();
    format!("{start}\n[... {} characters left out ...]\n{end}", total - MAX_OUTPUT_CHARS)
}

/// The first `n` characters.
pub fn head(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_formats_and_the_token_in_use() {
        assert_eq!(scrub("a github_pat_11AB_cd b", None), "a *** b");
        for p in ["ghp", "gho", "ghu", "ghs", "ghr"] {
            assert_eq!(scrub(&format!("x:{p}_abc123@"), None), "x:***@");
        }
        assert_eq!(scrub("say odd-token.", Some("odd-token")), "say ***.");
        let b = basic_auth("odd-token");
        assert_eq!(scrub(&format!("Basic {b}"), Some("odd-token")), "Basic ***");
        assert_eq!(scrub("nothing", Some("")), "nothing");
        assert_eq!(scrub("sighs_ ghx_abc", None), "sighs_ ghx_abc");
    }

    #[test]
    fn truncates_on_characters() {
        let exact = "é".repeat(MAX_OUTPUT_CHARS);
        assert_eq!(truncate_output(&exact), exact);
        // Start and end stay, the middle goes.
        let long = format!("S{exact}E");
        let cut = truncate_output(&long);
        let (start, end) = cut.split_once("\n[... 2 characters left out ...]\n").unwrap();
        assert_eq!(start, format!("S{}", "é".repeat(KEPT_START_CHARS - 1)));
        assert_eq!(end, format!("{}E", "é".repeat(MAX_OUTPUT_CHARS - KEPT_START_CHARS - 1)));
        assert_eq!(head("äöü", 2), "äö");
    }
}

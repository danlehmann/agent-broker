//! Tool declarations and argument validation, shared by the shim and the daemon.

use serde_json::{Map, Value, json};

use crate::error::{Result, refuse};

pub type Args = Map<String, Value>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    String,
    Integer,
    Boolean,
}

impl Type {
    fn name(self) -> &'static str {
        match self {
            Type::String => "string",
            Type::Integer => "integer",
            Type::Boolean => "boolean",
        }
    }

    fn accepts(self, v: &Value) -> bool {
        match self {
            Type::String => v.is_string(),
            Type::Integer => v.is_i64(),
            Type::Boolean => v.is_boolean(),
        }
    }
}

/// How the shim and daemon cooperate on a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// The daemon does everything.
    Plain,
    /// One step; the shim adds data from the checkout and the reply may carry a blob.
    Download,
    /// Two steps; the shim uploads a blob in the second.
    Upload,
}

pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    /// (name, type, required)
    pub args: &'static [(&'static str, Type, bool)],
    pub flow: Flow,
}

impl Tool {
    /// Whether the tool works on one resource, named by the optional `repo` argument.
    pub fn takes_repo(&self) -> bool {
        self.args.iter().any(|a| a.0 == "repo")
    }

    pub fn json(&self) -> Value {
        let props: Map<String, Value> =
            self.args.iter().map(|(n, t, _)| (n.to_string(), json!({"type": t.name()}))).collect();
        let required: Vec<&str> = self.args.iter().filter(|a| a.2).map(|a| a.0).collect();
        json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": props,
                "required": required,
                "additionalProperties": false,
            },
        })
    }

    pub fn validate(&self, args: &Args) -> Result<()> {
        for (name, _, required) in self.args {
            if *required && !args.contains_key(*name) {
                return refuse(format!("missing argument '{name}'"));
            }
        }
        for (name, value) in args {
            let Some((_, ty, _)) = self.args.iter().find(|a| a.0 == name) else {
                return refuse(format!("unknown argument '{name}'"));
            };
            if !ty.accepts(value) {
                return refuse(format!("argument '{name}' must be of type {}", ty.name()));
            }
        }
        Ok(())
    }
}

/// All tools of all services.
pub fn tools() -> &'static [Tool] {
    crate::github::TOOLS
}

pub fn find(name: &str) -> Option<&'static Tool> {
    tools().iter().find(|t| t.name == name)
}

pub fn str_arg<'a>(args: &'a Args, name: &str) -> Option<&'a str> {
    args.get(name).and_then(Value::as_str)
}

pub fn int_arg(args: &Args, name: &str) -> Option<i64> {
    args.get(name).and_then(Value::as_i64)
}

pub fn bool_arg(args: &Args, name: &str) -> bool {
    args.get(name).and_then(Value::as_bool).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(tool: &str, args: Value) -> std::result::Result<(), String> {
        find(tool).unwrap().validate(args.as_object().unwrap()).map_err(|e| e.public().to_string())
    }

    #[test]
    fn validates() {
        assert!(check("github_pr_comment", json!({"number": 1, "body": "x"})).is_ok());
        for (args, message) in [
            (json!({"number": 1}), "missing argument 'body'"),
            (json!({"number": 1, "body": "x", "z": 1}), "unknown argument 'z'"),
            (json!({"number": "1", "body": "x"}), "argument 'number' must be of type integer"),
            (json!({"number": true, "body": "x"}), "argument 'number' must be of type integer"),
            (json!({"number": 1.0, "body": "x"}), "argument 'number' must be of type integer"),
            (json!({"number": 1, "body": null}), "argument 'body' must be of type string"),
        ] {
            assert_eq!(check("github_pr_comment", args).unwrap_err(), message);
        }
        assert_eq!(
            check("github_push", json!({"workspace": "/x", "branch": "b", "force": 1})),
            Err("argument 'force' must be of type boolean".into())
        );
    }

    #[test]
    fn declarations_are_consistent() {
        assert_eq!(tools().len(), 10);
        for t in tools() {
            assert!(t.name.starts_with("github_"));
            assert_eq!(t.takes_repo(), t.name != "github_repos");
            assert_eq!(t.json()["inputSchema"]["additionalProperties"], false);
        }
    }
}

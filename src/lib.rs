//! composeguard: a fast security and best-practice linter for Docker Compose files.

pub mod config;
pub mod output;
pub mod rules;

use serde::Serialize;
use serde_yaml::Value;
use std::collections::HashMap;

pub use config::Config;

/// Finding severity, ordered from least to most severe.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, serde::Deserialize, Hash,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "warning" | "warn" => Ok(Severity::Warning),
            "error" => Ok(Severity::Error),
            "never" | "none" => Err("never".into()),
            o => Err(format!("unknown severity '{o}'")),
        }
    }
}

/// A single lint finding.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub service: String,
    pub message: String,
    pub line: usize,
}

/// Findings for one file.
#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub path: String,
    pub findings: Vec<Finding>,
}

/// Lint compose file contents. Returns an error string if the YAML cannot be parsed.
pub fn lint_str(src: &str, cfg: &Config) -> Result<Vec<Finding>, String> {
    if src
        .lines()
        .any(|l| l.trim_start().starts_with('#') && l.contains("composeguard-ignore-file"))
    {
        return Ok(vec![]);
    }
    let doc: Value = serde_yaml::from_str(src).map_err(|e| format!("invalid YAML: {e}"))?;
    let services = match doc.get("services").and_then(Value::as_mapping) {
        Some(m) => m,
        None => return Ok(vec![]),
    };
    let layout = layout(src);
    let mut out = Vec::new();
    for (k, svc) in services {
        let Some(name) = k.as_str() else { continue };
        let info = layout.get(name);
        for mut f in rules::check_service(name, svc) {
            if !cfg.enabled(f.rule) {
                continue;
            }
            if let Some(info) = info {
                if info.ignored.iter().any(|i| i == f.rule || i == "all") {
                    continue;
                }
                f.line = info.key_line(rule_key(f.rule)).unwrap_or(info.line);
            }
            if let Some(sev) = cfg.severity_override(f.rule) {
                f.severity = sev;
            }
            out.push(f);
        }
    }
    out.sort_by(|a, b| a.line.cmp(&b.line).then(a.rule.cmp(b.rule)));
    Ok(out)
}

fn rule_key(id: &str) -> &'static str {
    match id {
        "CG001" => "privileged",
        "CG002" => "network_mode",
        "CG003" => "pid",
        "CG004" => "ipc",
        "CG005" | "CG017" => "volumes",
        "CG006" => "image",
        "CG009" => "environment",
        "CG010" => "cap_add",
        "CG012" => "read_only",
        "CG013" => "ports",
        "CG014" => "user",
        "CG015" | "CG016" => "security_opt",
        "CG018" => "userns_mode",
        _ => "",
    }
}

#[derive(Debug, Default)]
struct ServiceLayout {
    line: usize,
    keys: HashMap<String, usize>,
    ignored: Vec<String>,
}

impl ServiceLayout {
    fn key_line(&self, key: &str) -> Option<usize> {
        self.keys.get(key).copied()
    }
}

fn parse_ignore(line: &str) -> Option<Vec<String>> {
    let idx = line.find("composeguard-ignore")?;
    let rest = &line[idx + "composeguard-ignore".len()..];
    if rest.starts_with("-file") {
        return None;
    }
    let rest = rest.trim_start_matches(':').trim();
    if rest.is_empty() {
        return Some(vec!["all".into()]);
    }
    Some(
        rest.split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_uppercase())
            .collect(),
    )
}

/// Best-effort line mapping of services and their top-level keys, plus inline ignore comments.
/// An ignore comment applies to the service whose block contains it, or to the
/// service declared on the line directly below it.
fn layout(src: &str) -> HashMap<String, ServiceLayout> {
    let mut map: HashMap<String, ServiceLayout> = HashMap::new();
    let mut in_services = false;
    let mut svc_indent: Option<usize> = None;
    let mut key_indent: Option<usize> = None;
    let mut current: Option<String> = None;
    let mut pending: Vec<String> = Vec::new();
    for (i, raw) in src.lines().enumerate() {
        let lineno = i + 1;
        let trimmed = raw.trim_start();
        let indent = raw.len() - trimmed.len();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            if let Some(ids) = parse_ignore(trimmed) {
                pending.extend(ids);
            }
            continue;
        }
        if indent == 0 {
            in_services = trimmed.starts_with("services:");
            current = None;
            svc_indent = None;
            pending.clear();
            continue;
        }
        if !in_services {
            continue;
        }
        let key = trimmed
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches(|c| c == '"' || c == '\'');
        let inline_ignore = raw.find('#').and_then(|p| parse_ignore(&raw[p..]));
        if svc_indent.is_none() {
            svc_indent = Some(indent);
        }
        if Some(indent) == svc_indent && trimmed.contains(':') {
            let entry = map.entry(key.to_string()).or_default();
            entry.line = lineno;
            entry.ignored.append(&mut pending);
            if let Some(ids) = inline_ignore {
                entry.ignored.extend(ids);
            }
            current = Some(key.to_string());
            key_indent = None;
            continue;
        }
        if let Some(cur) = &current {
            let entry = map.get_mut(cur).expect("current exists");
            entry.ignored.append(&mut pending);
            if let Some(ids) = inline_ignore {
                entry.ignored.extend(ids);
            }
            if key_indent.is_none() {
                key_indent = Some(indent);
            }
            if Some(indent) == key_indent && trimmed.contains(':') {
                entry.keys.entry(key.to_string()).or_insert(lineno);
            }
        }
    }
    map
}

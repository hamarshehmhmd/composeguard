//! Output formatters: human, json, sarif, github.

use crate::rules::RULES;
use crate::{FileReport, Severity};
use serde_json::json;

pub fn human(reports: &[FileReport]) -> String {
    let mut out = String::new();
    let mut total = 0;
    for r in reports {
        for f in &r.findings {
            total += 1;
            out.push_str(&format!(
                "{}:{}  {:<7}  {}  {}\n",
                r.path,
                f.line,
                f.severity.as_str(),
                f.rule,
                f.message
            ));
        }
    }
    let count = |s: Severity| {
        reports
            .iter()
            .flat_map(|r| &r.findings)
            .filter(|f| f.severity == s)
            .count()
    };
    out.push_str(&format!(
        "\n{} problem(s) in {} file(s): {} error, {} warning, {} info\n",
        total,
        reports.len(),
        count(Severity::Error),
        count(Severity::Warning),
        count(Severity::Info)
    ));
    out
}

pub fn json(reports: &[FileReport]) -> String {
    serde_json::to_string_pretty(reports).expect("serializable")
}

pub fn sarif(reports: &[FileReport]) -> String {
    let level = |s: Severity| match s {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    };
    let rules: Vec<_> = RULES
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "shortDescription": { "text": r.description },
                "helpUri": format!("https://github.com/hamarshehmhmd/composeguard#{}", r.id.to_lowercase()),
                "defaultConfiguration": { "level": level(r.severity) }
            })
        })
        .collect();
    let results: Vec<_> = reports
        .iter()
        .flat_map(|r| {
            r.findings.iter().map(move |f| {
                json!({
                    "ruleId": f.rule,
                    "level": level(f.severity),
                    "message": { "text": f.message },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": r.path.trim_start_matches("./") },
                            "region": { "startLine": f.line.max(1) }
                        }
                    }]
                })
            })
        })
        .collect();
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "composeguard",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/hamarshehmhmd/composeguard",
                "rules": rules
            }},
            "results": results
        }]
    });
    serde_json::to_string_pretty(&doc).expect("serializable")
}

pub fn github(reports: &[FileReport]) -> String {
    let mut out = String::new();
    for r in reports {
        for f in &r.findings {
            let kind = match f.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Info => "notice",
            };
            out.push_str(&format!(
                "::{kind} file={},line={},title={}::{}\n",
                r.path,
                f.line.max(1),
                f.rule,
                f.message.replace('%', "%25").replace('\n', "%0A")
            ));
        }
    }
    out
}

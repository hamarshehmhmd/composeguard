//! `.composeguard.yaml` configuration.

use crate::Severity;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Default config file name searched in the working directory.
pub const DEFAULT_CONFIG: &str = ".composeguard.yaml";

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Rule IDs to disable entirely.
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Lowest severity that makes the process exit non-zero (default: warning).
    #[serde(default)]
    pub fail_on: Option<String>,
    /// Per-rule severity overrides.
    #[serde(default)]
    pub severity: HashMap<String, Severity>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        if text.trim().is_empty() {
            return Ok(Self::default());
        }
        let cfg: Config = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        for id in cfg.ignore.iter().chain(cfg.severity.keys()) {
            if crate::rules::rule(&id.to_uppercase()).is_none() {
                return Err(format!("unknown rule id '{id}'"));
            }
        }
        Ok(cfg)
    }

    pub fn enabled(&self, id: &str) -> bool {
        !self.ignore.iter().any(|i| i.eq_ignore_ascii_case(id))
    }

    pub fn severity_override(&self, id: &str) -> Option<Severity> {
        self.severity
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(id))
            .map(|(_, v)| *v)
    }
}

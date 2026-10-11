use clap::{Parser, ValueEnum};
use composeguard::config::{Config, DEFAULT_CONFIG};
use composeguard::{FileReport, Severity, lint_str, output, rules::RULES};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Human,
    Json,
    Sarif,
    Github,
}

/// Fast security and best-practice linter for Docker Compose files.
///
/// Exit codes: 0 = no findings at or above --fail-on, 1 = findings, 2 = usage/parse error.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Compose files to lint. Defaults to compose.yaml / docker-compose.yml variants in the current directory.
    files: Vec<PathBuf>,
    /// Output format.
    #[arg(short, long, value_enum, default_value = "human")]
    format: Format,
    /// Config file (default: .composeguard.yaml if present).
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Minimum severity that causes exit code 1: info, warning, error, never.
    #[arg(long)]
    fail_on: Option<String>,
    /// Disable a rule (repeatable).
    #[arg(long = "ignore", value_name = "RULE")]
    ignore: Vec<String>,
    /// List all rules and exit.
    #[arg(long)]
    list_rules: bool,
}

const DEFAULT_FILES: &[&str] = &[
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
];

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.list_rules {
        for r in RULES {
            println!(
                "{}  {:<8} {:<24} {}",
                r.id,
                r.severity.as_str(),
                r.name,
                r.description
            );
        }
        return ExitCode::SUCCESS;
    }
    let mut cfg = match &cli.config {
        Some(p) => Config::load(p),
        None if Path::new(DEFAULT_CONFIG).exists() => Config::load(Path::new(DEFAULT_CONFIG)),
        None => Ok(Config::default()),
    }
    .unwrap_or_else(|e| fatal(&format!("config error: {e}")));
    cfg.ignore.extend(cli.ignore.iter().cloned());

    let fail_on = cli
        .fail_on
        .clone()
        .or(cfg.fail_on.clone())
        .unwrap_or_else(|| "warning".into());
    let threshold: Option<Severity> = match fail_on.parse() {
        Ok(s) => Some(s),
        Err(e) if e == "never" => None,
        Err(e) => fatal(&e),
    };

    let files: Vec<PathBuf> = if cli.files.is_empty() {
        DEFAULT_FILES
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect()
    } else {
        cli.files.clone()
    };
    if files.is_empty() {
        fatal("no compose file found; pass a path");
    }

    let mut reports = Vec::new();
    for f in &files {
        let src =
            std::fs::read_to_string(f).unwrap_or_else(|e| fatal(&format!("{}: {e}", f.display())));
        let findings =
            lint_str(&src, &cfg).unwrap_or_else(|e| fatal(&format!("{}: {e}", f.display())));
        reports.push(FileReport {
            path: f.display().to_string(),
            findings,
        });
    }

    let text = match cli.format {
        Format::Human => output::human(&reports),
        Format::Json => output::json(&reports),
        Format::Sarif => output::sarif(&reports),
        Format::Github => output::github(&reports),
    };
    print!("{text}");
    if matches!(cli.format, Format::Json | Format::Sarif) {
        println!();
    }

    let failed = threshold
        .map(|t| {
            reports
                .iter()
                .flat_map(|r| &r.findings)
                .any(|f| f.severity >= t)
        })
        .unwrap_or(false);
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("composeguard: {msg}");
    std::process::exit(2)
}

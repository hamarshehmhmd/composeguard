use composeguard::{Config, Severity, lint_str};
use std::collections::BTreeSet;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn ids(src: &str, cfg: &Config) -> BTreeSet<&'static str> {
    lint_str(src, cfg)
        .unwrap()
        .into_iter()
        .map(|f| f.rule)
        .collect()
}

#[test]
fn insecure_fixture_triggers_every_rule() {
    let got = ids(&fixture("insecure.yml"), &Config::default());
    for r in composeguard::rules::RULES {
        assert!(got.contains(r.id), "expected {} to fire, got {got:?}", r.id);
    }
}

#[test]
fn secure_fixture_is_clean() {
    let f = lint_str(&fixture("secure.yml"), &Config::default()).unwrap();
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn interpolated_secret_not_flagged() {
    let f = lint_str(&fixture("insecure.yml"), &Config::default()).unwrap();
    let secrets: Vec<_> = f.iter().filter(|f| f.rule == "CG009").collect();
    assert_eq!(secrets.len(), 1);
    assert!(secrets[0].message.contains("DB_PASSWORD"));
}

#[test]
fn localhost_db_port_not_flagged() {
    let f = lint_str(&fixture("insecure.yml"), &Config::default()).unwrap();
    let ports: Vec<_> = f.iter().filter(|f| f.rule == "CG013").collect();
    assert_eq!(ports.len(), 1);
    assert!(ports[0].message.contains("5432"));
}

#[test]
fn line_numbers_point_at_keys() {
    let f = lint_str(&fixture("insecure.yml"), &Config::default()).unwrap();
    let line = |id: &str| f.iter().find(|x| x.rule == id).unwrap().line;
    assert_eq!(line("CG001"), 4);
    assert_eq!(line("CG005"), 14);
    assert_eq!(line("CG006"), 3);
    assert_eq!(line("CG007"), 2);
}

#[test]
fn inline_ignores_apply() {
    let got = ids(&fixture("ignored.yml"), &Config::default());
    assert!(got.is_empty(), "{got:?}");
}

#[test]
fn ignore_file_directive() {
    assert!(ids(&fixture("skipfile.yml"), &Config::default()).is_empty());
}

#[test]
fn config_disables_and_overrides() {
    let cfg = Config::parse("ignore: [CG007, CG011]\nseverity:\n  CG001: warning\n").unwrap();
    let f = lint_str(&fixture("insecure.yml"), &cfg).unwrap();
    assert!(!f.iter().any(|x| x.rule == "CG007" || x.rule == "CG011"));
    assert_eq!(
        f.iter().find(|x| x.rule == "CG001").unwrap().severity,
        Severity::Warning
    );
}

#[test]
fn config_rejects_unknown_rule() {
    assert!(Config::parse("ignore: [CG999]").is_err());
}

#[test]
fn invalid_yaml_is_error() {
    assert!(lint_str("services: [", &Config::default()).is_err());
}

#[test]
fn port_parsing() {
    use composeguard::rules::exposed_db_port;
    assert_eq!(exposed_db_port("3306:3306"), Some(3306));
    assert_eq!(exposed_db_port("0.0.0.0:5432:5432/tcp"), Some(5432));
    assert_eq!(exposed_db_port("127.0.0.1:5432:5432"), None);
    assert_eq!(exposed_db_port("8080:80"), None);
    assert_eq!(exposed_db_port("5432"), None);
}

#[test]
fn long_syntax_volume_and_ports() {
    let src = "services:\n  a:\n    image: x:1\n    volumes:\n      - type: bind\n        source: /var/run/docker.sock\n        target: /s\n    ports:\n      - target: 27017\n        published: 27017\n";
    let got = ids(src, &Config::default());
    assert!(got.contains("CG005") && got.contains("CG013"), "{got:?}");
}

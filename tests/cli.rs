use std::process::Command;

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_composeguard"))
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn exit_codes() {
    assert_eq!(run(&["tests/fixtures/insecure.yml"]).0, 1);
    assert_eq!(run(&["tests/fixtures/secure.yml"]).0, 0);
    assert_eq!(
        run(&["--fail-on", "never", "tests/fixtures/insecure.yml"]).0,
        0
    );
    assert_eq!(run(&["does-not-exist.yml"]).0, 2);
}

#[test]
fn sarif_is_valid_json() {
    let (_, out) = run(&["-f", "sarif", "tests/fixtures/insecure.yml"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["version"], "2.1.0");
    assert!(!v["runs"][0]["results"].as_array().unwrap().is_empty());
}

#[test]
fn json_and_github_formats() {
    let (_, out) = run(&["-f", "json", "tests/fixtures/insecure.yml"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(v[0]["findings"].as_array().unwrap().len() > 10);
    let (_, gh) = run(&["-f", "github", "tests/fixtures/insecure.yml"]);
    assert!(gh.contains("::error file=tests/fixtures/insecure.yml,line=4,title=CG001::"));
}

#[test]
fn list_rules() {
    let (code, out) = run(&["--list-rules"]);
    assert_eq!(code, 0);
    assert!(out.contains("CG018"));
}

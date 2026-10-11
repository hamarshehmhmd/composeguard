//! Rule catalogue and checks.

use crate::{Finding, Severity};
use serde_yaml::Value;

/// Static metadata for a rule.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub description: &'static str,
}

pub const RULES: &[Rule] = &[
    Rule {
        id: "CG001",
        name: "privileged",
        severity: Severity::Error,
        description: "Service runs in privileged mode",
    },
    Rule {
        id: "CG002",
        name: "host-network",
        severity: Severity::Error,
        description: "Service uses network_mode: host",
    },
    Rule {
        id: "CG003",
        name: "host-pid",
        severity: Severity::Error,
        description: "Service shares the host PID namespace",
    },
    Rule {
        id: "CG004",
        name: "host-ipc",
        severity: Severity::Warning,
        description: "Service shares the host IPC namespace",
    },
    Rule {
        id: "CG005",
        name: "docker-socket",
        severity: Severity::Error,
        description: "Docker socket is mounted into the container",
    },
    Rule {
        id: "CG006",
        name: "unpinned-image",
        severity: Severity::Warning,
        description: "Image uses the latest tag or no tag",
    },
    Rule {
        id: "CG007",
        name: "no-healthcheck",
        severity: Severity::Info,
        description: "Service has no healthcheck",
    },
    Rule {
        id: "CG008",
        name: "no-restart-policy",
        severity: Severity::Info,
        description: "Service has no restart policy",
    },
    Rule {
        id: "CG009",
        name: "plaintext-secret",
        severity: Severity::Error,
        description: "Secret-looking environment variable has a literal value",
    },
    Rule {
        id: "CG010",
        name: "dangerous-capability",
        severity: Severity::Error,
        description: "cap_add includes ALL or SYS_ADMIN",
    },
    Rule {
        id: "CG011",
        name: "no-resource-limits",
        severity: Severity::Info,
        description: "Service has no memory/CPU limits",
    },
    Rule {
        id: "CG012",
        name: "writable-rootfs",
        severity: Severity::Info,
        description: "Root filesystem is not read_only",
    },
    Rule {
        id: "CG013",
        name: "db-port-exposed",
        severity: Severity::Warning,
        description: "Database port published on all interfaces",
    },
    Rule {
        id: "CG014",
        name: "root-user",
        severity: Severity::Warning,
        description: "Service runs as root or sets no user",
    },
    Rule {
        id: "CG015",
        name: "unconfined-security-opt",
        severity: Severity::Error,
        description: "seccomp or apparmor set to unconfined",
    },
    Rule {
        id: "CG016",
        name: "no-new-privileges",
        severity: Severity::Info,
        description: "no-new-privileges is not set in security_opt",
    },
    Rule {
        id: "CG017",
        name: "sensitive-host-mount",
        severity: Severity::Error,
        description: "Sensitive host path is bind-mounted",
    },
    Rule {
        id: "CG018",
        name: "host-userns",
        severity: Severity::Warning,
        description: "Service uses userns_mode: host",
    },
];

pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

const DB_PORTS: &[u16] = &[
    3306, 5432, 6379, 27017, 9200, 11211, 5984, 1433, 1521, 9042, 26257,
];
const SECRET_HINTS: &[&str] = &[
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
];
const SENSITIVE_PATHS: &[&str] = &[
    "/", "/etc", "/proc", "/sys", "/root", "/boot", "/dev", "/var/run", "/run",
];

fn s(v: &Value) -> Option<String> {
    match v {
        Value::String(x) => Some(x.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn get<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_mapping()?.get(Value::String(k.to_string()))
}

fn str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Sequence(seq)) => seq.iter().filter_map(s).collect(),
        Some(other) => s(other).into_iter().collect(),
        None => vec![],
    }
}

/// Run all rules against one service definition.
pub fn check_service(name: &str, svc: &Value) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut add = |id: &str, msg: String| {
        let r = rule(id).expect("known rule");
        out.push(Finding {
            rule: r.id,
            severity: r.severity,
            service: name.to_string(),
            message: msg,
            line: 0,
        });
    };

    if get(svc, "privileged").and_then(Value::as_bool) == Some(true) {
        add(
            "CG001",
            format!("service '{name}' runs privileged; drop it and grant only needed capabilities"),
        );
    }
    let mode = |k: &str| get(svc, k).and_then(s).unwrap_or_default();
    if mode("network_mode") == "host" {
        add("CG002", format!("service '{name}' uses host networking"));
    }
    if mode("pid") == "host" {
        add(
            "CG003",
            format!("service '{name}' shares the host PID namespace"),
        );
    }
    if mode("ipc") == "host" {
        add(
            "CG004",
            format!("service '{name}' shares the host IPC namespace"),
        );
    }
    if mode("userns_mode") == "host" {
        add(
            "CG018",
            format!("service '{name}' disables user namespace remapping"),
        );
    }

    // Volumes
    for vol in volume_sources(get(svc, "volumes")) {
        if vol.contains("docker.sock") {
            add(
                "CG005",
                format!(
                    "service '{name}' mounts the Docker socket ({vol}), which grants root on the host"
                ),
            );
        } else {
            let p = vol.trim_end_matches('/');
            let p = if p.is_empty() { "/" } else { p };
            if SENSITIVE_PATHS.contains(&p) {
                add(
                    "CG017",
                    format!("service '{name}' bind-mounts sensitive host path '{vol}'"),
                );
            }
        }
    }

    // Image
    if let Some(img) = get(svc, "image").and_then(s)
        && !img.contains('@')
    {
        let last = img.rsplit('/').next().unwrap_or(&img);
        match last.split_once(':') {
            None => add(
                "CG006",
                format!("image '{img}' has no tag; pin a version or digest"),
            ),
            Some((_, "latest")) => add(
                "CG006",
                format!("image '{img}' uses :latest; pin a version or digest"),
            ),
            _ => {}
        }
    }

    if get(svc, "healthcheck").is_none() {
        add("CG007", format!("service '{name}' has no healthcheck"));
    }
    let has_restart = get(svc, "restart").is_some()
        || get(svc, "deploy")
            .and_then(|d| get(d, "restart_policy"))
            .is_some();
    if !has_restart {
        add("CG008", format!("service '{name}' has no restart policy"));
    }

    // Environment
    for (k, v) in env_pairs(get(svc, "environment")) {
        let up = k.to_uppercase();
        if SECRET_HINTS.iter().any(|h| up.contains(h))
            && let Some(v) = v
        {
            let interpolated = v.starts_with('$') || v.is_empty();
            if !interpolated && !up.ends_with("_FILE") {
                add(
                    "CG009",
                    format!(
                        "environment variable '{k}' in service '{name}' has a literal value; use secrets or ${{VAR}} interpolation"
                    ),
                );
            }
        }
    }

    for cap in str_list(get(svc, "cap_add")) {
        let c = cap.to_uppercase();
        let c = c.trim_start_matches("CAP_");
        if c == "ALL" || c == "SYS_ADMIN" {
            add("CG010", format!("service '{name}' adds capability {cap}"));
        }
    }

    let limits = get(svc, "mem_limit").is_some()
        || get(svc, "cpus").is_some()
        || get(svc, "deploy")
            .and_then(|d| get(d, "resources"))
            .and_then(|r| get(r, "limits"))
            .is_some();
    if !limits {
        add("CG011", format!("service '{name}' has no resource limits"));
    }
    if get(svc, "read_only").and_then(Value::as_bool) != Some(true) {
        add(
            "CG012",
            format!("service '{name}' has a writable root filesystem; set read_only: true"),
        );
    }

    for p in str_list(get(svc, "ports"))
        .into_iter()
        .chain(long_ports(get(svc, "ports")))
    {
        if let Some(port) = exposed_db_port(&p) {
            add(
                "CG013",
                format!(
                    "service '{name}' publishes database port {port} on all interfaces; bind to 127.0.0.1"
                ),
            );
        }
    }

    match get(svc, "user").and_then(s) {
        None => add(
            "CG014",
            format!("service '{name}' sets no user and may run as root"),
        ),
        Some(u) if u == "root" || u == "0" || u.starts_with("0:") || u.starts_with("root:") => {
            add("CG014", format!("service '{name}' runs as root"))
        }
        _ => {}
    }

    let opts = str_list(get(svc, "security_opt"));
    for o in &opts {
        let lo = o.to_lowercase();
        if (lo.starts_with("seccomp") || lo.starts_with("apparmor")) && lo.contains("unconfined") {
            add("CG015", format!("service '{name}' sets security_opt '{o}'"));
        }
    }
    if !opts.iter().any(|o| {
        let lo = o.replace(' ', "").to_lowercase();
        lo == "no-new-privileges"
            || lo == "no-new-privileges:true"
            || lo == "no-new-privileges=true"
    }) {
        add(
            "CG016",
            format!("service '{name}' does not set no-new-privileges:true"),
        );
    }

    out
}

fn volume_sources(v: Option<&Value>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(Value::Sequence(seq)) = v {
        for item in seq {
            match item {
                Value::String(x) => {
                    let src = x.split(':').next().unwrap_or("");
                    if src.starts_with('/') || src.starts_with('.') || src.starts_with('~') {
                        out.push(src.to_string());
                    }
                }
                Value::Mapping(_) => {
                    if let Some(src) = get(item, "source").and_then(s)
                        && src.starts_with('/')
                    {
                        out.push(src);
                    }
                }
                _ => {}
            }
        }
    }
    out
}

fn env_pairs(v: Option<&Value>) -> Vec<(String, Option<String>)> {
    match v {
        Some(Value::Mapping(m)) => m.iter().filter_map(|(k, v)| Some((s(k)?, s(v)))).collect(),
        Some(Value::Sequence(seq)) => seq
            .iter()
            .filter_map(s)
            .map(|e| match e.split_once('=') {
                Some((k, v)) => (k.to_string(), Some(v.to_string())),
                None => (e, None),
            })
            .collect(),
        _ => vec![],
    }
}

fn long_ports(v: Option<&Value>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(Value::Sequence(seq)) = v {
        for item in seq.iter().filter(|i| i.is_mapping()) {
            let published = get(item, "published").and_then(s);
            let target = get(item, "target").and_then(s).unwrap_or_default();
            let ip = get(item, "host_ip").and_then(s);
            if let Some(p) = published {
                out.push(match ip {
                    Some(ip) => format!("{ip}:{p}:{target}"),
                    None => format!("{p}:{target}"),
                });
            }
        }
    }
    out
}

/// Returns the container DB port if a port spec publishes it on all interfaces.
pub fn exposed_db_port(spec: &str) -> Option<u16> {
    let spec = spec.split('/').next().unwrap_or(spec);
    let parts: Vec<&str> = spec.rsplitn(3, ':').collect();
    // parts reversed: [container, host?, ip?]
    let container = parts.first()?;
    let host_ip = if parts.len() == 3 {
        Some(parts[2])
    } else {
        None
    };
    if parts.len() == 1 {
        return None; // only container port; ephemeral host port, still all interfaces but rarely intended. skip
    }
    if let Some(ip) = host_ip
        && ip != "0.0.0.0"
        && ip != "::"
        && ip != "[::]"
    {
        return None;
    }
    let port: u16 = container.split('-').next()?.parse().ok()?;
    DB_PORTS.contains(&port).then_some(port)
}

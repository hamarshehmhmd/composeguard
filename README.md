# composeguard

[![CI](https://github.com/hamarshehmhmd/composeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/hamarshehmhmd/composeguard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hamarshehmhmd/composeguard)](https://github.com/hamarshehmhmd/composeguard/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A fast, single-binary linter that catches security and best-practice problems in Docker Compose files, built for CI.**

```console
$ composeguard docker-compose.yml
docker-compose.yml:4  error    CG001  service 'web' runs privileged; drop it and grant only needed capabilities
docker-compose.yml:14  error    CG005  service 'web' mounts the Docker socket (/var/run/docker.sock), which grants root on the host
docker-compose.yml:18  error    CG009  environment variable 'DB_PASSWORD' in service 'web' has a literal value; use secrets or ${VAR} interpolation
docker-compose.yml:22  warning  CG013  service 'db' publishes database port 5432 on all interfaces; bind to 127.0.0.1
```

## Why composeguard?

Most teams lint their Dockerfiles with [Hadolint](https://github.com/hadolint/hadolint) and scan images for CVEs with [Docker Scout](https://docs.docker.com/scout/). The Compose file is where containers actually get their privileges: `privileged: true`, a mounted `docker.sock`, `network_mode: host`, a Postgres port open to the internet, a password pasted into `environment:`. Neither Hadolint nor Scout reports those settings. composeguard does.

- **One static binary.** No Node or Python runtime. Download it and run it.
- **CI-native output.** Human, JSON, **SARIF** (GitHub code scanning) and **GitHub annotations**.
- **Predictable exit codes.** `0` clean, `1` findings at or above `--fail-on`, `2` usage or parse error.
- **Stable rule IDs** (`CG001`…) so you can ignore rules in config or inline.

## Install

**Prebuilt binaries** (Linux x86_64/arm64, macOS x86_64/arm64, Windows x86_64) are on the [releases page](https://github.com/hamarshehmhmd/composeguard/releases):

```sh
VERSION=v0.1.0
curl -sSL "https://github.com/hamarshehmhmd/composeguard/releases/download/$VERSION/composeguard-$VERSION-x86_64-unknown-linux-gnu.tar.gz" | tar xz
sudo mv composeguard-$VERSION-x86_64-unknown-linux-gnu/composeguard /usr/local/bin/
```

**From source** (Rust 1.88+):

```sh
cargo install --git https://github.com/hamarshehmhmd/composeguard
```

## Quickstart

```sh
composeguard                          # lints compose.yaml / docker-compose.yml in the current dir
composeguard stack.yml other.yml      # specific files
composeguard -f sarif > results.sarif # SARIF for code scanning
composeguard --fail-on error          # only fail on errors
composeguard --ignore CG011           # disable a rule
composeguard --list-rules
```

From a clone of this repository you can also lint the fixtures (the insecure file should report findings; the secure file should be clean):

```sh
cargo build --release
./target/release/composeguard tests/fixtures/insecure.yml
./target/release/composeguard tests/fixtures/secure.yml
```

## Rules

| ID | Name | Severity | What it catches |
|----|------|----------|-----------------|
| CG001 | privileged | error | `privileged: true` |
| CG002 | host-network | error | `network_mode: host` |
| CG003 | host-pid | error | `pid: host` |
| CG004 | host-ipc | warning | `ipc: host` |
| CG005 | docker-socket | error | `docker.sock` bind mount |
| CG006 | unpinned-image | warning | image with `:latest` or no tag |
| CG007 | no-healthcheck | info | no `healthcheck` |
| CG008 | no-restart-policy | info | no `restart` / `deploy.restart_policy` |
| CG009 | plaintext-secret | error | `*PASSWORD*`, `*TOKEN*`, `*SECRET*`, `*API_KEY*`… with a literal value (not `${VAR}`, not `*_FILE`) |
| CG010 | dangerous-capability | error | `cap_add: ALL` or `SYS_ADMIN` |
| CG011 | no-resource-limits | info | no `deploy.resources.limits`, `mem_limit` or `cpus` |
| CG012 | writable-rootfs | info | `read_only` not `true` |
| CG013 | db-port-exposed | warning | DB ports (5432, 3306, 6379, 27017, 9200, …) published on all interfaces |
| CG014 | root-user | warning | no `user`, or `user: root` / `0` |
| CG015 | unconfined-security-opt | error | `seccomp:unconfined` / `apparmor:unconfined` |
| CG016 | no-new-privileges | info | `security_opt` lacks `no-new-privileges:true` |
| CG017 | sensitive-host-mount | error | bind mount of `/`, `/etc`, `/proc`, `/sys`, `/root`, `/dev`, `/run`, … |
| CG018 | host-userns | warning | `userns_mode: host` |

## Configuration

Put a `.composeguard.yaml` in the directory you run from (or pass `--config`):

```yaml
ignore: [CG011]          # disable rules
fail_on: warning         # info | warning | error | never
severity:
  CG007: warning         # per-rule severity override
```

### Inline ignores

```yaml
services:
  # composeguard-ignore: CG007 CG008     <- applies to the service below
  agent:
    image: portainer/agent:2.21.0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # composeguard-ignore CG005
```

A bare `# composeguard-ignore` silences every rule for that service; `# composeguard-ignore-file` skips the whole file.

## GitHub Actions

```yaml
name: compose-lint
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  composeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hamarshehmhmd/composeguard@v0.1.0
        with:
          files: docker-compose.yml
          fail-on: error
          sarif-file: composeguard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: composeguard.sarif
```

Inputs: `files` (space-separated; default: autodetect Compose files in the working directory), `format` (default `github`), `fail-on` (default `warning`), `version` (default `latest`), `sarif-file` (optional). Works on Linux, macOS and Windows runners.

## How it compares

These tools answer different questions. Use more than one if you need to.

| | composeguard | [Hadolint](https://github.com/hadolint/hadolint) | [Docker Scout](https://docs.docker.com/scout/) | [compose-lint](https://github.com/tmatens/compose-lint) | [DCLint](https://github.com/zavoloklom/docker-compose-linter) |
|---|---|---|---|---|---|
| Reads | Compose files | Dockerfiles | Container images | Compose files | Compose files |
| Focus | Security and runtime hardening | Dockerfile best practices and ShellCheck | Image SBOM, CVEs, and licenses | Security misconfigurations (OWASP / CIS Docker Benchmark) | Style, structure, ordering, and schema |
| Runtime | Single static Rust binary | Single binary | Docker CLI / Desktop plugin and service | Python 3.11+ (`pip install compose-lint`) or a Docker image | Node.js |
| SARIF | Yes | Yes | Yes (`docker scout cves --format sarif`) | Yes | No built-in formatter (json, compact, stylish, junit, codeclimate) |
| Auto-fix | No | No | No | Yes, for some rules (dry-run first) | Yes, for some formatting rules |
| Schema validation | No (use `docker compose config`) | n/a | n/a | No | Yes |

**Hadolint** lints Dockerfiles only. A [request for Compose support](https://github.com/hadolint/hadolint/issues/1091) is open; Hadolint does not read `compose.yaml` / `docker-compose.yml`. The two tools do not overlap: Hadolint checks how an image is built, composeguard checks how Compose runs it.

**Docker Scout** analyzes images. It builds an SBOM and matches packages against a vulnerability database. It does not report Compose settings such as `privileged: true`, a mounted `docker.sock`, host networking, or a literal password in `environment:`. An image with no known CVEs can still run with full host access if the Compose file asks for it. Pair Scout (or another image scanner such as [Trivy](https://github.com/aquasecurity/trivy)) with a Compose linter.

**compose-lint** is the closest specialist tool: a Python linter with a larger Compose-security rule set, optional auto-fix, SARIF, and a GitHub Action. It also merges override files, `include:` / `extends:`, and related env files the way Compose would deploy them. composeguard v0.1 does not resolve those merges and does not inspect `env_file`. If you want the broader rule set and autofix, try compose-lint. composeguard is a smaller single static binary (no Python runtime), with inline `# composeguard-ignore` comments, GitHub annotations, and an 18-rule set that is easy to turn on as a blocking CI check.

**DCLint** is more mature for formatting, structure, and schema validation. Two of its fifteen rules overlap security concerns ([unbound port interfaces](https://github.com/zavoloklom/docker-compose-linter/blob/main/docs/rules/no-unbound-port-interfaces-rule.md) and [explicit image tags](https://github.com/zavoloklom/docker-compose-linter/blob/main/docs/rules/service-image-require-explicit-tag-rule.md)); the rest are style and structure. Pair it with a security-focused Compose linter.

Broader IaC scanners also look at Compose:

- [KICS](https://github.com/Checkmarx/kics) by Checkmarx [supports Docker Compose](https://docs.kics.io/latest/platforms/) among many other platforms and publishes a [catalog of Compose queries](https://docs.kics.io/latest/queries/dockercompose-queries/).
- [Semgrep](https://github.com/semgrep/semgrep) ships a `p/docker-compose` ruleset as part of a general-purpose scanner (`semgrep --config p/docker-compose`).

composeguard is young (v0.1): line numbers are best-effort, `extends` / `include` and multiple-file merges are not resolved, and environment values from `env_file` are not inspected.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [GOOD_FIRST_ISSUES.md](GOOD_FIRST_ISSUES.md), and the [good first issues](https://github.com/hamarshehmhmd/composeguard/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) on GitHub. Security reports: [SECURITY.md](SECURITY.md).

## License

MIT

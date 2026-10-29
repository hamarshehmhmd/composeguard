# composeguard

[![CI](https://github.com/hamarshehmhmd/composeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/hamarshehmhmd/composeguard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hamarshehmhmd/composeguard)](https://github.com/hamarshehmhmd/composeguard/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A fast, single-binary linter that catches security and best-practice problems in Docker Compose files, built for CI.**

```console
$ composeguard docker-compose.yml
docker-compose.yml:4   error    CG001  service 'web' runs privileged; drop it and grant only needed capabilities
docker-compose.yml:14  error    CG005  service 'web' mounts the Docker socket (/var/run/docker.sock), which grants root on the host
docker-compose.yml:18  error    CG009  environment variable 'DB_PASSWORD' in service 'web' has a literal value; use secrets or ${VAR} interpolation
docker-compose.yml:22  warning  CG013  service 'db' publishes database port 5432 on all interfaces; bind to 127.0.0.1
```

## Why composeguard?

Most teams lint their Dockerfiles with hadolint, but the Compose file is where containers actually get their privileges: `privileged: true`, a mounted `docker.sock`, `network_mode: host`, a Postgres port open to the internet, a password pasted into `environment:`. composeguard checks for exactly those mistakes.

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

## How it compares

Honest summary; pick what fits.

| | composeguard | [hadolint](https://github.com/hadolint/hadolint) | [dclint](https://github.com/zavoloklom/docker-compose-linter) |
|---|---|---|---|
| Lints | Compose files | Dockerfiles | Compose files |
| Focus | Security + runtime hardening | Dockerfile best practices, shellcheck | Style, structure, ordering, schema |
| Runtime | Single static binary | Single binary | Node.js |
| SARIF | Yes | Yes | Yes |
| Auto-fix | No | No | Yes (some rules) |
| Schema validation | No (use `docker compose config`) | n/a | Yes |

hadolint and composeguard are complementary: hadolint checks how the image is built; composeguard checks how it is run. dclint is more mature for formatting and schema checks; composeguard is narrower and focused on security. composeguard is young (v0.1): line numbers are best-effort, `extends`/`include` and multiple-file merges are not resolved, and environment values from `env_file` are not inspected.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [GOOD_FIRST_ISSUES.md](GOOD_FIRST_ISSUES.md). Security reports: [SECURITY.md](SECURITY.md).

## License

MIT

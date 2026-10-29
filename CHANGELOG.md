# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-11

### Added
- 18 rules (CG001–CG018) covering privileged mode, host namespaces, Docker socket and sensitive host mounts, unpinned images, healthchecks, restart policies, plaintext secrets, dangerous capabilities, resource limits, read-only rootfs, exposed database ports, root user, unconfined seccomp/apparmor and no-new-privileges.
- Output formats: human, JSON, SARIF 2.1.0, GitHub annotations.
- `.composeguard.yaml` config (ignore, fail_on, per-rule severity) and inline `composeguard-ignore` comments.
- CI exit codes (0/1/2), composite GitHub Action, prebuilt binaries for Linux, macOS and Windows.

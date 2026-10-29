# Contributing

Thanks for helping! Issues and PRs are welcome.

## Development

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

All three must pass; CI runs them on Linux, macOS and Windows.

## Adding a rule

1. Add a `Rule` entry to `RULES` in `src/rules.rs` with the next free ID (`CG0xx`). IDs are stable and never reused.
2. Implement the check in `check_service`.
3. If the rule maps to a compose key, add it to `rule_key` in `src/lib.rs` so line numbers point at it.
4. Add a fixture case in `tests/fixtures/` and a test in `tests/lint.rs`. Make sure `secure.yml` stays clean.
5. Document it in the README rules table and CHANGELOG.

Keep false positives low: when in doubt, prefer `info` severity.

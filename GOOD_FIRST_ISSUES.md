# Good first issues

Small, well-scoped tasks for new contributors. Comment on (or open) an issue before starting.

1. **`--version` in SARIF `semanticVersion`** – add the field to the SARIF driver.
2. **Rule: `CG019` mutable bind mounts of source code in production** – flag `.:/app` without `:ro`.
3. **Rule: `CG020` `cap_drop: [ALL]` missing** – info-level hardening hint.
4. **Read `env_file`** – scan referenced env files for CG009.
5. **Directory input** – `composeguard ./deploy` should find compose files recursively.
6. **`--quiet` flag** – suppress the summary line in human output.
7. **More DB ports for CG013** – e.g. ClickHouse 8123/9000, Neo4j 7687, RabbitMQ 5672.
8. **Docs** – a `docs/rules/CG0xx.md` page per rule with rationale and fix examples.

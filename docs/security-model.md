# Security model

The CLI reads a repository the operator points at and writes a report inside that repository. It is not a sandbox for untrusted execution in general. Some tools still run code or parsers influenced by the repository.

## Assumptions

- The operator is authorized to scan the target.
- The operator's user account is the trust boundary for host commands.
- Docker is the preferred isolation for Trivy and Semgrep.
- A finished report is a record of checks that ran, not a proof that no vulnerabilities remain.

## Untrusted repository

Path checks:

- `assertRepositoryPath` uses `realpath` and requires a directory.
- `assertPathInsideRepository` rejects paths and symlink chains that leave the repository.
- `assertNoEscapingSymlinks` walks the tree and refuses the scan when a symlink escapes or cannot be resolved. `node_modules`, `.git`, build output, and `security-reports` are not descended into.

Host environment for scanner processes is an allowlist (`PATH`, `HOME`, `USER`, `TMPDIR`, Docker and XDG variables) plus explicit scan variables. Parent secrets are not forwarded by default.

Raw tool output copied with `--keep-raw` is redacted. Keys whose names look like secrets, tokens, or code lines are replaced. Pattern redaction is incomplete.

## Docker

Compose runs Trivy and Semgrep with the images pinned in `compose/security-scan.compose.yml`. The repository mount and capability drops are defined there. The CLI does not pass the Docker socket into those scanners.

If Compose cannot run, an already installed `trivy` or `semgrep` binary may run on the host. The tool reason states that this is not the pinned image. Coverage is not silently described as the pinned scan. If neither runtime exists, a required scanner fails the scan.

The CLI does not download scanner binaries.

## Dart

`dart analyze` runs on the host when a `package_config.json` already exists. The CLI does not run `dart pub get`.

Analyzer plugins are repository code. Direct `plugins:` or `analyzer.plugins` entries, and the same keys in a resolvable `include:`, skip host analysis unless `--allow-dart-plugins` is set. Missing includes, unsupported include shapes, package includes that cannot be resolved, and relative includes outside the repository also skip analysis. Cycles are followed once and do not loop. A repository file cannot grant the opt-in.

Host analysis without plugins still executes the Dart analyzer on the host for a repository you chose to scan.

## Gitleaks

Optional and off unless enabled. The parser drops `Secret` and `Match`. Reports say a rule matched. They do not store the secret value and do not prove the secret is valid.

## Audit artifacts

A findings file and its sidecar are attacker-controlled if the repository or the path you pass is untrusted. The CLI validates shape and compares attestation with the commit it recorded. It does not sign artifacts and does not prove a hunt process ran.

Contradictory commit, repository path, or dirty state is rejected. Legacy manifests remain attachable only when the audit does not claim a commit.

## Safe use

Scan repositories you are allowed to read. Prefer the pinned containers. Do not pass `--allow-dart-plugins` for a repository you do not trust. Do not treat exit 0 as a complete security assessment. Do not publish raw reports that may still contain unredacted strings the patterns missed.

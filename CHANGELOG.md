# Changelog

## 0.5.0

- Host Dart analysis follows `include:` chains and skips when plugin safety cannot be determined unless `--allow-dart-plugins` is set.
- Source-audit attachment records agent-attested identity separately from the CLI scan commit. A missing sidecar stays legacy or unbound. Contradictory metadata is rejected. A match is not proof the hunt ran.
- Optional Gitleaks history scanning when the binary is already installed and explicitly enabled.
- SARIF 2.1.0 export alongside canonical findings.
- Offline Semgrep runs bundled rules instead of skipping the tool, and says registry packs were not loaded.
- Trivy and Semgrep can use installed host binaries only when Docker Compose is unavailable. The report marks those runs as unpinned.
- Scan-owned raw cache directories are removed after the report is written.
- Package name is `security-scan-cli`. The package is not published.

## 0.4.0

- Unified workflow, finding accounting, and Cloudflare attachment.

## 0.3.0

- Initial public repository release.

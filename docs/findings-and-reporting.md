# Findings and reporting

Canonical JSON is the source of truth. Markdown and SARIF are projections.

## Canonical finding

`createFinding` assigns:

- a random `id` for that write
- a stable `fingerprint` from category, location, rule or advisory, and CWE or CVE
- redacted title, description, and evidence
- one `sources` entry for the tool that produced the row
- `verification: "potential"` unless a later import sets an audit verdict
- `provenance: "deterministic"` unless import sets `source-audit`

SCA findings record package presence as confirmed and reachability as `not_analyzed`. Publisher advisory text is not an independent check.

## Parser accounting

Each parser returns accepted findings and a discard count.

- `ToolRun.findingCount` is accepted canonical findings for that run.
- `ToolRun.discardedDuringParse` is rows the parser rejected.
- Omitted `discardedDuringParse` on an old manifest means "not recorded", not zero.
- `FindingSummary.rawToolFindingsTotal` is accepted plus recorded discards.
- `preDedupeCollected` is findings before fingerprint dedupe.
- `duplicatesRemoved` is the count removed by dedupe, not parser loss.
- `normalizedUnique` is the length of the written findings array.

Attach uses `buildAttachFindingSummary`. It keeps the scan-time discard and dedupe figures and adds importable rows. Repeating an attach does not multiply sources.

## Deduplication

The fingerprint is the group key, with two explicit exceptions:

- Trivy `DS002` and Semgrep's missing-user Dockerfile rule share a fingerprint when the path is the same.
- Cleartext HTTP sinks in one file stay separate and share `relatedGroupId`.

A higher severity wins inside a group. Distinct CVEs stay distinct because advisory identity is part of the SCA fingerprint.

## Status

| Tool status | Meaning |
|---|---|
| `passed` | Completed with no canonical findings |
| `findings` | Completed and produced findings |
| `failed` | Required failure, timeout, bad document, or partial Semgrep coverage |
| `skipped` | Optional tool did not run |
| `unsupported` | No adapter |

Overall `incomplete` forces exit 2. `complete_with_findings` is still a finished scan; the threshold decides exit 0 or 1.

## Reports

`writeReports` validates findings, writes a sibling staging directory, and renames it onto the scan directory. Failure deletes the staging directory. Scan ids include a timestamp and a short commit prefix, so a new scan does not replace an older report directory.

Files:

- `findings.json` — canonical findings
- `scan-manifest.json` — schema version 2, tool runs, git, finding summary, optional source audit
- `report.md` — human summary, including that comprehensive coverage is not claimed
- `findings.sarif.json` — SARIF 2.1.0 with rule id, level, message, path, and fingerprint
- `workflow-run.json` — workflow record when the scan created one

SARIF does not copy redacted secret text into the message. It does not invent code flows or fixes the canonical finding does not have.

## Older manifests

Schema version stays 2. `git`, `commitBinding`, `commitIdentity`, and `discardedDuringParse` are optional. A manifest without `git` can still accept an audit that does not name a commit. That result is `legacy-scan`, not a verified match. An audit that names a commit is rejected when the manifest has no commit to compare.

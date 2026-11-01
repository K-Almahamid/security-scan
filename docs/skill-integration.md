# Audit skill integration

Deterministic scanners run inside `security-scan scan`. Agent audit skills do not.

The CLI never starts Cursor, a model API, or the Cloudflare hunt. Attaching a findings file does not mean the skill was invoked. `workflow register-cloudflare` stores an operator statement. Treat that statement as self-reported.

## What the CLI does

| Command | Effect |
|---|---|
| `audit validate` | Schema-check a findings file. No report write. |
| `audit import` | Print importable and rejected counts. No report write. |
| `audit attach` | Merge importable findings when identity checks pass. |
| `workflow register-cloudflare` | Record invocation claims and phase names the operator supplies. |
| `workflow assess` | Compare the manifest, workflow file, and deterministic exit code. |

Cloudflare findings are a JSON array validated by the vendored schema. Items do not accept extra properties, so commit identity is not stored inside a finding.

## Attestation

Optional sidecar: `findings.json` may have `findings.identity.json` beside it.

```json
{
  "version": 1,
  "repositoryPath": "/absolute/path/to/repository",
  "commit": "<40 lowercase hex characters>",
  "dirty": false
}
```

- Missing sidecar: no attestation. The binding is `unbound` when the scan recorded git, or `legacy-scan` when the manifest has no `git` object.
- Malformed JSON, an unknown key, or `version` other than 1: attach fails with exit 3 and does not change the report.
- `--target-commit` is the same kind of attestation. If both name a commit, they must be equal.
- `repositoryPath`, when present, must be the canonical `--repo` path.
- When both the sidecar and the manifest know `dirty`, they must agree.
- A match requires the attested commit to equal `manifest.git.commit` and the recorded dirty state to be false.
- HEAD at attach time is observed again. If it differs from the scanned commit, that is recorded. It is not treated as the audit identity and it is not proof the hunt ran.

`commitBinding: "matched"` and `commitIdentity.agreement: "attested-matches-scan"` mean the attestation equals the clean commit the CLI stored. They do not mean this process watched the hunt.

## Provenance

Imported findings use provenance `source-audit`. Deterministic findings stay `deterministic`. Deduplication can place both on one fingerprint when the identity matches. Rejected Cloudflare records stay in `source-audit-records.json` and are not promoted to confirmed findings.

## Adding another skill

Do not reuse the Cloudflare phase list unless that skill actually uses those phases. Add a validator and an attach path that:

- accepts only a validated artifact
- records orchestration as an external agent, not as a CLI execution
- stores attested commit identity beside the artifact
- rejects contradictory identity
- leaves legacy artifacts attachable without calling them verified
- stays idempotent when attach is repeated

The skill document for operators remains separate from the adapter registry.

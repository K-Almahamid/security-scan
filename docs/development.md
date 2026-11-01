# Development

## Setup

```bash
git clone https://github.com/K-Almahamid/security-scan.git
cd security-scan
npm ci
npm run verify
```

Node.js 20 or newer. CI is Ubuntu with Node.js 22 (`.github/workflows/verify.yml`). Local development is macOS or Linux. Windows is not covered by tests or CI.

`npm run verify` runs unit tests, vendored Cloudflare validator tests, typecheck, ESLint, and `tsc`. Docker and Dart checks inside the unit tests run when those tools are on `PATH`. A skip is not a pass. This repository's `npm test` does not skip those checks when the tools exist.

## Commands

| Script | Purpose |
|---|---|
| `npm test` | Unit tests via `node --test` |
| `npm run test:cloudflare-validators` | Vendored findings schema tests |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run lint` | ESLint |
| `npm run build` | Emit `dist/` |
| `npm run verify` | All of the above |
| `npm run test:containers` | Builds, then scans this repository with a 10 minute timeout. Not part of `verify`. |

CLI smoke after a build:

```bash
node dist/cli.js version
node dist/cli.js --help
```

`security-scan version` prints the `version` field in `package.json`.

## Conventions

- Conventional commits.
- Runtime dependency is Zod. Do not add a dependency for a one-off helper.
- New scanner behavior belongs in an adapter and a registry capability.
- Do not change exit codes 0–4.
- Fingerprints are part of dedupe identity. Change them only to fix a demonstrated defect, with a regression test.
- Do not scan unrelated repositories in tests. Use fixtures under `test/fixtures/`.

## Packaging

The npm name is `security-scan-cli`. The package `security-scan` is a different project. This package is not published by CI.

```bash
npm pack --dry-run
```

The tarball includes `dist/`, `compose/`, `rules/`, `schemas/`, `skill/`, `docs/`, and the license and top-level docs. Confirm it does not contain `.env` files, credentials, or `node_modules`.

An isolated install check, from a temporary directory:

```bash
npm pack
npm install --prefix /tmp/security-scan-install ./security-scan-cli-0.5.0.tgz
/tmp/security-scan-install/node_modules/.bin/security-scan version
```

Replace the tarball name if the version changed. Do not `npm publish` unless a maintainer asks.

## Docs

User setup stays in the README. Design notes stay in `docs/`. When behavior changes, update the README section and the matching doc in the same change. Do not describe a scanner or skill workflow that the CLI does not implement.

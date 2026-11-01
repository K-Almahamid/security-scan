# Contributing

## Setup

```bash
git clone https://github.com/K-Almahamid/security-scan.git
cd security-scan
npm ci
npm run verify
```

Node.js 20 or newer is required. CI runs on Ubuntu with Node.js 22. macOS is used for local development. Windows is not tested.

`npm run verify` runs unit tests, the vendored Cloudflare validator tests, typecheck, lint, and the TypeScript build. Docker and Dart tests run when those tools are visible. A skip is not a pass.

See [docs/development.md](docs/development.md) for verification, packaging, and fixtures. Scanner and skill steps below are the short form of [docs/scanner-integration.md](docs/scanner-integration.md) and [docs/skill-integration.md](docs/skill-integration.md).

## Adding a scanner

1. Implement `ToolAdapter` in `src/adapters.ts`: prerequisite check, execution, and a parser that returns canonical findings.
2. Add a capability in `src/registry.ts`. Unknown adapter ids fail at startup.
3. The scan loop calls `dispatchTool`. Do not add a tool-specific branch there.
4. Redact secret evidence. Do not download binaries. If the tool is optional, a missing binary skips that tool. A required tool still fails the scan when neither the pinned image nor an already installed binary can run.

## Adding an audit skill

Discovery, invocation, completion, validation, and attachment are separate. The CLI validates and attaches a findings file. It does not launch an agent. The Cloudflare skill has its own phase list. A new skill does not inherit those phases or a `matched` commit claim. Put agent-attested commit identity in a sidecar, not inside the findings array.

## Commits

Use conventional commits. Do not commit secrets.

# Scanner integration

A scanner is a `ToolAdapter` plus one capability in `src/registry.ts`. `dispatchTool` looks up the adapter by id. Do not add a per-tool branch in the scanner.

There is no plugin marketplace and no loader of arbitrary repository code.

## Adapter contract

`ToolAdapter` in `src/types.ts` is:

- `id` — stable adapter id (`trivy`, `semgrep`, `dart-analyze`, `gitleaks`)
- `checkPrerequisites` — return a string to skip or fail, or null to run
- `execute` — return canonical findings and a `ToolRun`

Planning fields live on the capability, not in the orchestrator:

- applicability (`isApplicable`, `isAutoApplicable`)
- config key under `tools`
- prerequisites such as `docker-compose`, `dart-sdk`, or `gitleaks`
- `requiredWhenScheduled` — false means a missing binary skips; true means it fails the scan

Unknown adapter ids fail in `assertValidCapabilityRegistry` before tools run.

## Execution

`resolveScannerRuntime` prefers Docker Compose for Trivy and Semgrep. A host binary is used only when Compose is unavailable, and the tool run says that binary is not the pinned image. The CLI does not download binaries.

`runCommand` kills the process group on timeout, caps captured output, and passes `allowedHostEnvironment` rather than the full parent environment.

Parsers return `ScannerParse`: accepted findings, the raw row count, and `discarded`. `finishJsonTool` stores discards only when the findings array it persists is the parsed array. A timeout or invalid document stores no findings from that tool.

## Semgrep partial coverage

`PartialParsing` and other non-blocking errors keep parsed findings and set the tool status to `failed` through `applySemgrepCompletionPolicy`. Exit code 0 from the process does not make that run complete. Blocking errors drop that tool's findings. Offline mode uses `rules/semgrep` and does not load Semgrep registry packs. The run should say registry coverage was not loaded.

## Required and optional

| Scanner | Required when planned | Missing runtime |
|---|---|---|
| Trivy | yes | failed, scan incomplete |
| Semgrep, for a supported language component | yes | failed, scan incomplete |
| Dart analyzer | no | skipped |
| Gitleaks | no, and off unless `tools.gitleaks.enabled` is `true` or `"auto"` | skipped |

Dart also skips when analyzer plugins are declared or an `include:` chain cannot be verified, unless the operator passed `--allow-dart-plugins`. Target config cannot set that flag.

## Tests for a new scanner

- Prerequisite missing, and the required versus optional status.
- Parser acceptance and at least one malformed row counted as discarded.
- Secret-like evidence redacted or omitted.
- Dedupe against an existing finding with the same fingerprint.
- A fake adapter test already shows `dispatchTool` runs a registered adapter without a scanner-specific branch. Extend that pattern instead of special-casing the orchestrator.

## Minimal shape

```typescript
const exampleAdapter: ToolAdapter = {
  id: "example",
  async checkPrerequisites() {
    return null;
  },
  async execute(plan) {
    return {
      findings: [],
      run: {
        id: plan.id,
        adapter: plan.adapter,
        componentId: plan.componentId,
        status: "passed",
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        durationMs: 0,
        exitCode: 0,
        version: null,
        reason: null,
        logPath: null,
        findingCount: 0,
        discardedDuringParse: 0,
      },
    };
  },
};
```

Register the same `id` on a `CapabilityDefinition` and add it to the known adapter set. Ship a parser that returns `ScannerParse` if the tool emits a document.

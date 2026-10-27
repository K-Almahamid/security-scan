import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { doctorExitCode, runDoctor } from "../src/doctor.js";
import { DEFAULT_MAX_CAPTURE_BYTES, runCommand } from "../src/execution.js";
import { allowedHostEnvironment } from "../src/execution.js";
import { writeReports } from "../src/reports.js";
import {
  assessWorkflowFromReport,
  hasMaterialInconsistencies,
  workflowAssessExitCode,
} from "../src/workflow-assess.js";
import {
  createInitialWorkflowRun,
  loadWorkflowRun,
  recordDeterministicScanCompletion,
  registerCloudflareAgentOutcome,
  updateWorkflowRun,
  WORKFLOW_RUN_FILENAME,
} from "../src/workflow-run.js";
import { finalizeToolExecution } from "../src/adapters.js";
import type { ScanManifest } from "../src/types.js";
import { defaultConfig } from "../src/config.js";
import { assertRepositoryPath, profileRepository } from "../src/profile.js";
import { buildScanPlan } from "../src/planner.js";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function runCli(args: string[]) {
  return spawnSync(process.execPath, ["--import", "tsx", path.join(projectRoot, "src/cli.ts"), ...args], {
    cwd: projectRoot,
    encoding: "utf8",
  });
}

describe("doctor and workflow commands", () => {
  it("reports repository and docker prerequisites", async () => {
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-doctor-"));
    await writeFile(path.join(repo, "package.json"), JSON.stringify({ name: "fixture" }));
    const report = await runDoctor({ repo, workflowRequest: "deterministic-only" });
    const docker = report.checks.find((check) => check.id === "docker-compose");
    assert.ok(docker);
    assert.equal(report.deterministicReady, docker.status === "pass");
    assert.ok(report.checks.some((check) => check.id === "repository-path" && check.status === "pass"));
  });

  it("marks full-audit doctor as warning when Cloudflare skill is missing", async () => {
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-doctor-full-"));
    await writeFile(path.join(repo, "README.md"), "fixture\n");
    const report = await runDoctor({ repo, workflowRequest: "full" });
    const cloudflare = report.checks.find((check) => check.id === "cloudflare-security-audit-skill");
    assert.ok(cloudflare);
    if (cloudflare.status === "fail") {
      assert.equal(doctorExitCode(report), 1);
    }
  });
});

describe("workflow-run state", () => {
  it("records deterministic completion and rejects duplicate cloudflare completion", async () => {
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-wfrun-"));
    await writeFile(path.join(repo, "package.json"), JSON.stringify({ name: "fixture" }));
    const reportDir = path.join(repo, "security-reports", "scan-1");
    const startedAt = "2026-01-01T00:00:00.000Z";
    let record = createInitialWorkflowRun({
      scanId: "scan-1",
      repositoryPath: repo,
      request: "full",
      startedAt,
    });
    const manifest: ScanManifest = {
      schemaVersion: 2,
      scanId: "scan-1",
      repositoryPath: repo,
      startedAt,
      completedAt: "2026-01-01T00:05:00.000Z",
      overallStatus: "complete",
      mode: "standard",
      toolRuns: [],
      execution: {
        status: "complete",
        planned: 1,
        completed: 1,
        failed: 0,
        skipped: 0,
        unsupported: 0,
      },
      coverage: {
        comprehensive: false,
        plannedStatus: "complete",
        plannedChecks: [],
        supportedChecks: [],
        outOfScope: [],
        unsupported: [],
      },
      coverageGaps: [],
      counts: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        unknown: 0,
      },
      rawArtifactsPath: "/tmp/raw",
      reportDirectory: reportDir,
    };
    record = recordDeterministicScanCompletion(record, manifest);
    assert.equal(record.steps[0]?.status, "completed");
    await writeReports({
      reportDirectory: reportDir,
      profile: await profileRepository(repo, defaultConfig, new Date(startedAt)),
      plan: buildScanPlan(
        await profileRepository(repo, defaultConfig, new Date(startedAt)),
        defaultConfig,
      ),
      manifest,
      findings: [],
      workflowRun: record,
    });
    const loaded = await loadWorkflowRun(reportDir);
    assert.ok(loaded);
    await updateWorkflowRun(reportDir, (current) =>
      registerCloudflareAgentOutcome(current, {
        skillInstalled: true,
        delegationAvailable: true,
        sandboxAvailable: false,
        invoked: true,
        phasesCompleted: [
          "reconnaissance",
          "coverage-led-hunting",
          "candidate-validation",
          "structured-findings",
          "independent-verification",
          "reporting",
        ],
        status: "completed",
        findingsPath: "findings.json",
      }),
    );
    await assert.rejects(
      () =>
        updateWorkflowRun(reportDir, (current) =>
          registerCloudflareAgentOutcome(current, {
            skillInstalled: true,
            delegationAvailable: true,
            sandboxAvailable: false,
            invoked: true,
            phasesCompleted: ["reporting"],
            status: "completed",
          }),
        ),
      /already marked completed/,
    );
  });

  it("assesses deterministic-only completion from artifacts", async () => {
    const repo = await assertRepositoryPath(
      await mkdtemp(path.join(os.tmpdir(), "security-scan-assess-")),
    );
    const reportDir = path.join(repo, "security-reports", "fixture-scan");
    await cp(path.join(projectRoot, "test/fixtures/minimal-scan"), reportDir, { recursive: true });
    const manifestPath = path.join(reportDir, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ScanManifest;
    manifest.repositoryPath = repo;
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const result = await assessWorkflowFromReport({
      repo,
      scanDir: "security-reports/fixture-scan",
      request: "deterministic-only",
    });
    assert.equal(result.assessment.cloudflareStatus, "not_requested");
    assert.ok(["complete", "complete_with_findings"].includes(result.assessment.combinedStatus));
  });
});

describe("bounded subprocess output", () => {
  it("truncates oversized stdout without unbounded growth", async () => {
    const result = await runCommand(
      process.execPath,
      ["-e", "process.stdout.write('a'.repeat(500_000))"],
      {
        cwd: projectRoot,
        timeoutMs: 10_000,
        env: allowedHostEnvironment(),
        maxStdoutBytes: 4096,
      },
    );
    assert.equal(result.stdoutTruncated, true);
    assert.ok(Buffer.byteLength(result.stdout, "utf8") < 500_000);
    assert.match(result.stdout, /TRUNCATED/);
  });

  it("preserves small command output", async () => {
    const result = await runCommand(process.execPath, ["-e", "console.log('ok')"], {
      cwd: projectRoot,
      timeoutMs: 10_000,
      env: allowedHostEnvironment(),
      maxStdoutBytes: DEFAULT_MAX_CAPTURE_BYTES,
    });
    assert.equal(result.stdoutTruncated, false);
    assert.match(result.stdout, /ok/);
  });

  it("terminates oversized stderr without hanging", async () => {
    const result = await runCommand(
      process.execPath,
      ["-e", "while(true) process.stderr.write('x')"],
      {
        cwd: projectRoot,
        timeoutMs: 10_000,
        env: allowedHostEnvironment(),
        maxStderrBytes: 4096,
      },
    );
    assert.equal(result.stderrTruncated, true);
    const completion = finalizeToolExecution({
      family: "dart-analyze",
      exitCode: result.exitCode,
      timedOut: result.timedOut,
      outputTruncated: result.stdoutTruncated || result.stderrTruncated,
      documentValid: true,
      findings: [],
    });
    assert.equal(completion.status, "failed");
  });
});

describe("cli workflow integration", () => {
  it("exposes doctor and version 0.4.0", () => {
    const version = runCli(["version"]);
    assert.equal(version.status, 0);
    assert.match(version.stdout, /0\.4\.0/);
    const help = runCli(["help"]);
    assert.match(help.stdout, /doctor/);
    assert.match(help.stdout, /workflow assess/);
  });
});

async function writeFullWorkflowFixture(input: {
  repo: string;
  reportDir: string;
  scanId: string;
  manifest: ScanManifest;
  workflowExtras?: (record: ReturnType<typeof createInitialWorkflowRun>) => ReturnType<typeof createInitialWorkflowRun>;
}) {
  const startedAt = input.manifest.startedAt;
  let record = createInitialWorkflowRun({
    scanId: input.scanId,
    repositoryPath: input.repo,
    request: "full",
    startedAt,
  });
  record = recordDeterministicScanCompletion(record, input.manifest);
  if (input.workflowExtras) record = input.workflowExtras(record);
  await writeReports({
    reportDirectory: input.reportDir,
    profile: await profileRepository(input.repo, defaultConfig, new Date(startedAt)),
    plan: buildScanPlan(
      await profileRepository(input.repo, defaultConfig, new Date(startedAt)),
      defaultConfig,
    ),
    manifest: input.manifest,
    findings: [],
    workflowRun: record,
  });
}

describe("workflow assess integrity (phase 1.1)", () => {
  it("rejects assessing a full workflow report as deterministic-only", async () => {
    const repo = await assertRepositoryPath(
      await mkdtemp(path.join(os.tmpdir(), "security-scan-assess-downgrade-")),
    );
    await writeFile(path.join(repo, "package.json"), JSON.stringify({ name: "fixture" }));
    const reportDir = path.join(repo, "security-reports", "scan-full");
    const startedAt = "2026-01-01T00:00:00.000Z";
    const manifest: ScanManifest = {
      schemaVersion: 2,
      scanId: "scan-full",
      repositoryPath: repo,
      startedAt,
      completedAt: "2026-01-01T00:05:00.000Z",
      overallStatus: "complete",
      mode: "standard",
      toolRuns: [],
      execution: {
        status: "complete",
        planned: 1,
        completed: 1,
        failed: 0,
        skipped: 0,
        unsupported: 0,
      },
      coverage: {
        comprehensive: false,
        plannedStatus: "complete",
        plannedChecks: [],
        supportedChecks: [],
        outOfScope: [],
        unsupported: [],
      },
      coverageGaps: [],
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
      rawArtifactsPath: "/tmp/raw",
      reportDirectory: reportDir,
    };
    await writeFullWorkflowFixture({ repo, reportDir, scanId: "scan-full", manifest });
    await assert.rejects(
      () =>
        assessWorkflowFromReport({
          repo,
          scanDir: reportDir,
          request: "deterministic-only",
        }),
      /Cannot assess a full workflow report/,
    );
    const cli = runCli([
      "workflow",
      "assess",
      "--repo",
      repo,
      "--scan-dir",
      reportDir,
      "--workflow",
      "deterministic-only",
    ]);
    assert.equal(cli.status, 3);
  });

  it("does not treat manifest sourceAudit as attached when workflow-run says false", async () => {
    const repo = await assertRepositoryPath(
      await mkdtemp(path.join(os.tmpdir(), "security-scan-assess-attach-")),
    );
    await writeFile(path.join(repo, "package.json"), JSON.stringify({ name: "fixture" }));
    const reportDir = path.join(repo, "security-reports", "scan-attach");
    const startedAt = "2026-01-01T00:00:00.000Z";
    const manifest: ScanManifest = {
      schemaVersion: 2,
      scanId: "scan-attach",
      repositoryPath: repo,
      startedAt,
      completedAt: "2026-01-01T00:05:00.000Z",
      overallStatus: "complete",
      mode: "standard",
      toolRuns: [],
      execution: {
        status: "complete",
        planned: 1,
        completed: 1,
        failed: 0,
        skipped: 0,
        unsupported: 0,
      },
      coverage: {
        comprehensive: false,
        plannedStatus: "complete",
        plannedChecks: [],
        supportedChecks: [],
        outOfScope: [],
        unsupported: [],
      },
      coverageGaps: [],
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
      rawArtifactsPath: "/tmp/raw",
      reportDirectory: reportDir,
      sourceAudit: {
        status: "attached",
        methodology: "cloudflare-security-audit-skill",
        upstreamCommit: "abc",
        sourceFindingsPath: "findings.json",
        validatedAt: startedAt,
        orchestration: "cursor-agent",
        counts: { confirmed: 0, needs_validation: 0, rejected: 0 },
        note: "fixture",
      },
    };
    await writeFullWorkflowFixture({
      repo,
      reportDir,
      scanId: "scan-attach",
      manifest,
      workflowExtras: (record) =>
        registerCloudflareAgentOutcome(record, {
          skillInstalled: true,
          delegationAvailable: true,
          sandboxAvailable: false,
          invoked: true,
          phasesCompleted: [
            "reconnaissance",
            "coverage-led-hunting",
            "candidate-validation",
            "structured-findings",
            "independent-verification",
            "reporting",
          ],
          status: "completed",
        }),
    });
    const result = await assessWorkflowFromReport({ repo, scanDir: reportDir });
    assert.ok(result.inconsistencies.some((issue) => issue.includes("source audit attachment")));
    assert.equal(result.assessment.combinedStatus, "incomplete");
    assert.equal(
      workflowAssessExitCode(
        result.assessment,
        result.deterministicExitCode,
        result.inconsistencies,
        result.assessment.request,
      ),
      2,
    );
  });

  it("treats legacy reports without workflow-run as incomplete for --workflow full", async () => {
    const repo = await assertRepositoryPath(
      await mkdtemp(path.join(os.tmpdir(), "security-scan-legacy-full-")),
    );
    const reportDir = path.join(repo, "security-reports", "fixture-scan");
    await cp(path.join(projectRoot, "test/fixtures/minimal-scan"), reportDir, { recursive: true });
    const manifestPath = path.join(reportDir, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ScanManifest;
    manifest.repositoryPath = repo;
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const result = await assessWorkflowFromReport({
      repo,
      scanDir: reportDir,
      request: "full",
    });
    assert.equal(result.assessment.combinedStatus, "incomplete");
    assert.ok(hasMaterialInconsistencies(result.inconsistencies, "full"));
    assert.equal(
      workflowAssessExitCode(
        result.assessment,
        result.deterministicExitCode,
        result.inconsistencies,
        "full",
      ),
      2,
    );
  });

  it("rejects malformed workflow-run.json", async () => {
    const repo = await assertRepositoryPath(
      await mkdtemp(path.join(os.tmpdir(), "security-scan-malformed-wfrun-")),
    );
    await writeFile(path.join(repo, "package.json"), JSON.stringify({ name: "fixture" }));
    const reportDir = path.join(repo, "security-reports", "bad");
    await cp(path.join(projectRoot, "test/fixtures/minimal-scan"), reportDir, { recursive: true });
    const manifestPath = path.join(reportDir, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ScanManifest;
    manifest.repositoryPath = repo;
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    await writeFile(path.join(reportDir, WORKFLOW_RUN_FILENAME), "{ not-json");
    await assert.rejects(() => assessWorkflowFromReport({ repo, scanDir: reportDir }), /not valid JSON/);
    const cli = runCli(["workflow", "assess", "--repo", repo, "--scan-dir", reportDir, "--json"]);
    assert.equal(cli.status, 3);
  });

  it("marks registration completed with zero phases as incomplete on assess", async () => {
    const repo = await assertRepositoryPath(
      await mkdtemp(path.join(os.tmpdir(), "security-scan-zero-phases-")),
    );
    await writeFile(path.join(repo, "package.json"), JSON.stringify({ name: "fixture" }));
    const reportDir = path.join(repo, "security-reports", "scan-zero");
    const startedAt = "2026-01-01T00:00:00.000Z";
    const manifest: ScanManifest = {
      schemaVersion: 2,
      scanId: "scan-zero",
      repositoryPath: repo,
      startedAt,
      completedAt: "2026-01-01T00:05:00.000Z",
      overallStatus: "complete",
      mode: "standard",
      toolRuns: [],
      execution: {
        status: "complete",
        planned: 1,
        completed: 1,
        failed: 0,
        skipped: 0,
        unsupported: 0,
      },
      coverage: {
        comprehensive: false,
        plannedStatus: "complete",
        plannedChecks: [],
        supportedChecks: [],
        outOfScope: [],
        unsupported: [],
      },
      coverageGaps: [],
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
      rawArtifactsPath: "/tmp/raw",
      reportDirectory: reportDir,
    };
    await writeFullWorkflowFixture({
      repo,
      reportDir,
      scanId: "scan-zero",
      manifest,
      workflowExtras: (record) =>
        registerCloudflareAgentOutcome(record, {
          skillInstalled: true,
          delegationAvailable: true,
          sandboxAvailable: false,
          invoked: true,
          phasesCompleted: [],
          status: "completed",
        }),
    });
    const result = await assessWorkflowFromReport({ repo, scanDir: reportDir });
    assert.equal(result.assessment.combinedStatus, "incomplete");
    assert.equal(
      workflowAssessExitCode(
        result.assessment,
        result.deterministicExitCode,
        result.inconsistencies,
        result.assessment.request,
      ),
      2,
    );
  });

  it("uses exit code 3 for scanId mismatches between manifest and workflow-run", async () => {
    const repo = await assertRepositoryPath(
      await mkdtemp(path.join(os.tmpdir(), "security-scan-scanid-mismatch-")),
    );
    await writeFile(path.join(repo, "package.json"), JSON.stringify({ name: "fixture" }));
    const reportDir = path.join(repo, "security-reports", "scan-mismatch");
    const startedAt = "2026-01-01T00:00:00.000Z";
    const manifest: ScanManifest = {
      schemaVersion: 2,
      scanId: "manifest-scan",
      repositoryPath: repo,
      startedAt,
      completedAt: "2026-01-01T00:05:00.000Z",
      overallStatus: "complete",
      mode: "standard",
      toolRuns: [],
      execution: {
        status: "complete",
        planned: 1,
        completed: 1,
        failed: 0,
        skipped: 0,
        unsupported: 0,
      },
      coverage: {
        comprehensive: false,
        plannedStatus: "complete",
        plannedChecks: [],
        supportedChecks: [],
        outOfScope: [],
        unsupported: [],
      },
      coverageGaps: [],
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
      rawArtifactsPath: "/tmp/raw",
      reportDirectory: reportDir,
    };
    await writeFullWorkflowFixture({ repo, reportDir, scanId: "workflow-scan", manifest });
    const result = await assessWorkflowFromReport({ repo, scanDir: reportDir });
    assert.ok(result.inconsistencies.some((issue) => issue.includes("scanId")));
    assert.equal(
      workflowAssessExitCode(
        result.assessment,
        result.deterministicExitCode,
        result.inconsistencies,
        result.assessment.request,
      ),
      3,
    );
  });

  it("serializes workflow-run revisions across sequential updates", async () => {
    const repo = await assertRepositoryPath(
      await mkdtemp(path.join(os.tmpdir(), "security-scan-wfrun-race-")),
    );
    await writeFile(path.join(repo, "package.json"), JSON.stringify({ name: "fixture" }));
    const reportDir = path.join(repo, "security-reports", "scan-race");
    const startedAt = "2026-01-01T00:00:00.000Z";
    const manifest: ScanManifest = {
      schemaVersion: 2,
      scanId: "scan-race",
      repositoryPath: repo,
      startedAt,
      completedAt: "2026-01-01T00:05:00.000Z",
      overallStatus: "complete",
      mode: "standard",
      toolRuns: [],
      execution: {
        status: "complete",
        planned: 1,
        completed: 1,
        failed: 0,
        skipped: 0,
        unsupported: 0,
      },
      coverage: {
        comprehensive: false,
        plannedStatus: "complete",
        plannedChecks: [],
        supportedChecks: [],
        outOfScope: [],
        unsupported: [],
      },
      coverageGaps: [],
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
      rawArtifactsPath: "/tmp/raw",
      reportDirectory: reportDir,
    };
    await writeFullWorkflowFixture({ repo, reportDir, scanId: "scan-race", manifest });
    const first = await updateWorkflowRun(reportDir, (current) => {
      current.cloudflare.failureReason = "writer-a";
      return current;
    });
    const second = await updateWorkflowRun(reportDir, (current) => {
      current.cloudflare.failureReason = "writer-b";
      return current;
    });
    assert.equal(second.revision, first.revision + 1);
    const loaded = await loadWorkflowRun(reportDir);
    assert.equal(loaded?.cloudflare.failureReason, "writer-b");
  });

  it("normalizes findingsPath to a basename on registration", async () => {
    const repo = await assertRepositoryPath(
      await mkdtemp(path.join(os.tmpdir(), "security-scan-findings-path-")),
    );
    await writeFile(path.join(repo, "package.json"), JSON.stringify({ name: "fixture" }));
    const reportDir = path.join(repo, "security-reports", "scan-fp");
    const startedAt = "2026-01-01T00:00:00.000Z";
    const manifest: ScanManifest = {
      schemaVersion: 2,
      scanId: "scan-fp",
      repositoryPath: repo,
      startedAt,
      completedAt: "2026-01-01T00:05:00.000Z",
      overallStatus: "complete",
      mode: "standard",
      toolRuns: [],
      execution: {
        status: "complete",
        planned: 1,
        completed: 1,
        failed: 0,
        skipped: 0,
        unsupported: 0,
      },
      coverage: {
        comprehensive: false,
        plannedStatus: "complete",
        plannedChecks: [],
        supportedChecks: [],
        outOfScope: [],
        unsupported: [],
      },
      coverageGaps: [],
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
      rawArtifactsPath: "/tmp/raw",
      reportDirectory: reportDir,
    };
    await writeFullWorkflowFixture({ repo, reportDir, scanId: "scan-fp", manifest });
    await updateWorkflowRun(reportDir, (current) =>
      registerCloudflareAgentOutcome(current, {
        skillInstalled: true,
        delegationAvailable: true,
        sandboxAvailable: false,
        invoked: true,
        phasesCompleted: ["reporting"],
        status: "failed",
        findingsPath: "/tmp/outside/hunt-findings.json",
      }),
    );
    const loaded = await loadWorkflowRun(reportDir);
    assert.equal(loaded?.cloudflare.findingsPath, "hunt-findings.json");
  });

  it("keeps workflow assess --json stdout as valid JSON", async () => {
    const repo = await assertRepositoryPath(
      await mkdtemp(path.join(os.tmpdir(), "security-scan-assess-json-")),
    );
    const reportDir = path.join(repo, "security-reports", "fixture-scan");
    await cp(path.join(projectRoot, "test/fixtures/minimal-scan"), reportDir, { recursive: true });
    const manifestPath = path.join(reportDir, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ScanManifest;
    manifest.repositoryPath = repo;
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const cli = runCli([
      "workflow",
      "assess",
      "--repo",
      repo,
      "--scan-dir",
      "security-reports/fixture-scan",
      "--workflow",
      "deterministic-only",
      "--json",
    ]);
    assert.equal(cli.status, 0);
    assert.equal(cli.stderr, "");
    const payload = JSON.parse(cli.stdout) as { exitCode: number; assessment: { combinedStatus: string } };
    assert.equal(payload.exitCode, 0);
    assert.ok(payload.assessment.combinedStatus);
  });
});

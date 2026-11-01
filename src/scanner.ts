import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { createAdapters } from "./adapters.js";
import {
  loadConfig,
  resolveReportsDirectory,
  type SecurityScanConfig,
} from "./config.js";
import { allowedHostEnvironment, runCommand } from "./execution.js";
import { UsageError } from "./errors.js";
import {
  deduplicateFindings,
  redactSensitiveText,
  severityAtOrAbove,
} from "./findings.js";
import { buildScanPlan } from "./planner.js";
import {
  assertNoEscapingSymlinks,
  assertPathInsideRepository,
  assertRepositoryPath,
  profileRepository,
} from "./profile.js";
import {
  buildScanFindingSummary,
  coverageSummary,
  determineOverallStatus,
  executionSummary,
  findingCounts,
  writeReports,
} from "./reports.js";
import type {
  AdapterContext,
  AdapterResult,
  CanonicalFinding,
  ToolAdapter,
  OverallStatus,
  ScanManifest,
  Severity,
  ToolPlan,
  ToolRun,
} from "./types.js";
import {
  createInitialWorkflowRun,
  recordDeterministicScanCompletion,
  type WorkflowRunRecord,
} from "./workflow-run.js";
import type { WorkflowRequest } from "./workflow.js";

export interface ScanOptions {
  repo: string;
  configPath?: string;
  reportsDir?: string;
  offline?: boolean;
  jobs?: number;
  timeoutMs?: number;
  keepRaw?: boolean;
  failOn?: SecurityScanConfig["policy"]["failOn"];
  workflowRequest?: WorkflowRequest;
  allowDartPlugins?: boolean;
}

export interface ScanOutcome {
  manifest: ScanManifest;
  findings: CanonicalFinding[];
  exitCode: number;
}

/**
 * Profiles a repository, runs the planned adapters, and writes one report.
 *
 * A required tool that cannot run leaves the scan incomplete (exit 2).
 * An empty plan is a usage error (exit 3), not a clean scan.
 * The scan-owned raw cache is removed in `finally`, including when a tool throws.
 * Historical report directories are not deleted.
 *
 * @throws {UsageError} For an unusable repository, an escaping symlink, or an empty plan.
 */
export async function runSecurityScan(options: ScanOptions): Promise<ScanOutcome> {
  const startedAt = new Date();
  const repoPath = await assertRepositoryPath(options.repo);
  const loaded = await loadConfig(repoPath, options.configPath);
  const config = applyOverrides(loaded, options);
  const profile = await profileRepository(repoPath, config, startedAt);
  await assertNoEscapingSymlinks(repoPath);
  const plan = buildScanPlan(profile, config);
  if (plan.tools.length === 0) {
    throw new UsageError(
      "No scanner was planned. Refusing to report a successful scan without an executed check.",
    );
  }
  const git = await readRepositoryGit(repoPath);
  const scanId = createScanId(startedAt, git.commit);
  const workflowRequest = options.workflowRequest ?? "deterministic-only";
  let workflowRun: WorkflowRunRecord = createInitialWorkflowRun({
    scanId,
    repositoryPath: repoPath,
    request: workflowRequest,
    startedAt: startedAt.toISOString(),
  });
  const reportRoot = resolveReportsDirectory(
    repoPath,
    options.reportsDir ?? config.reportsDir,
  );
  await assertPathInsideRepository(repoPath, reportRoot);
  const reportDirectory = path.join(reportRoot, scanId);
  const repoHash = createHash("sha256").update(repoPath).digest("hex").slice(0, 16);
  const rawDirectory = path.join(
    os.homedir(),
    ".cache",
    "security-scan",
    repoHash,
    scanId,
    "raw",
  );
  try {
  await mkdir(rawDirectory, { recursive: true, mode: 0o700 });

  const composeFile = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "../compose/security-scan.compose.yml",
  );
  const context: AdapterContext = {
    repoPath,
    rawDirectory,
    composeFile,
    offline: config.tools.trivy.offline || options.offline === true,
    timeoutMs: options.timeoutMs ?? 20 * 60_000,
    exclude: config.exclude,
    allowDartPlugins: options.allowDartPlugins === true,
  };
  const adapters = createAdapters();
  const results = await mapConcurrent(
    plan.tools,
    Math.max(1, Math.min(options.jobs ?? 2, 8)),
    (toolPlan) => dispatchTool(adapters, toolPlan, context),
  );
  const collectedFindings = results.flatMap((result) => result.findings);
  const findings = deduplicateFindings(collectedFindings);
  const toolRuns = results.map((result) => result.run);
  const completedAt = new Date();
  const manifest: ScanManifest = {
    schemaVersion: 2,
    scanId,
    repositoryPath: repoPath,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    overallStatus: determineOverallStatus(toolRuns, findings),
    mode: "standard",
    toolRuns,
    execution: executionSummary(toolRuns),
    coverage: coverageSummary(plan, toolRuns),
    coverageGaps: plan.coverageGaps,
    counts: findingCounts(findings),
    git,
    findingSummary: buildScanFindingSummary({
      toolRuns,
      collectedFindings,
      normalizedFindings: findings,
    }),
    rawArtifactsPath: rawDirectory,
    reportDirectory,
  };
  workflowRun = recordDeterministicScanCompletion(workflowRun, manifest);
  await writeReports({
    reportDirectory,
    profile,
    plan,
    manifest,
    findings,
    workflowRun,
  });

  if (options.keepRaw) {
    const destination = path.join(reportDirectory, "raw");
    await mkdir(destination, { recursive: true, mode: 0o700 });
    await copyRedactedRaw(rawDirectory, destination);
  }
  const threshold = options.failOn ?? config.policy.failOn;
  const exitCode = scanExitCode(manifest.overallStatus, findings, threshold);
  return { manifest, findings, exitCode };
  } finally {
    await rm(path.dirname(rawDirectory), { recursive: true, force: true });
  }
}

/**
 * Maps a finished deterministic scan to exit codes 0, 1, 2, or 3.
 *
 * Incomplete execution is 2 even when findings exist. Configuration errors are 3.
 * Exit 1 means at least one finding is at or above the threshold on a completed scan.
 * Exit 4 is reserved for unexpected orchestration failures in the CLI, not here.
 */
export function scanExitCode(
  status: OverallStatus,
  findings: CanonicalFinding[],
  threshold: Exclude<Severity, "unknown">,
): number {
  if (status === "configuration_error") return 3;
  if (status === "incomplete") return 2;
  return findings.some((finding) => severityAtOrAbove(finding.severity, threshold)) ? 1 : 0;
}

function applyOverrides(
  config: SecurityScanConfig,
  options: ScanOptions,
): SecurityScanConfig {
  return {
    ...config,
    reportsDir: options.reportsDir ?? config.reportsDir,
    tools: {
      ...config.tools,
      trivy: {
        ...config.tools.trivy,
        offline: options.offline ?? config.tools.trivy.offline,
      },
    },
    policy: {
      ...config.policy,
      failOn: options.failOn ?? config.policy.failOn,
    },
  };
}

/**
 * Runs one planned tool through its adapter.
 *
 * A missing prerequisite skips an optional tool and fails a required tool.
 * Adapter exceptions become failed tool runs, except {@link UsageError}, which
 * aborts the scan because the target itself is unsafe to continue.
 */
export async function dispatchTool(
  adapters: Map<string, ToolAdapter>,
  toolPlan: ToolPlan,
  context: AdapterContext,
): Promise<AdapterResult> {
  const adapter = adapters.get(toolPlan.adapter);
  if (!adapter) return unavailableResult(toolPlan, "No adapter is registered", "unsupported");
  try {
    const reason = await adapter.checkPrerequisites(toolPlan, context);
    if (reason) {
      return unavailableResult(toolPlan, reason, toolPlan.required ? "failed" : "skipped");
    }
    return await adapter.execute(toolPlan, context);
  } catch (error) {
    if (error instanceof UsageError) throw error;
    return unavailableResult(
      toolPlan,
      redactSensitiveText(error instanceof Error ? error.message : String(error)),
      "failed",
    );
  }
}

function unavailableResult(
  plan: ToolPlan,
  reason: string,
  status: ToolRun["status"],
): AdapterResult {
  const now = new Date().toISOString();
  return {
    findings: [],
    run: {
      id: plan.id,
      adapter: plan.adapter,
      componentId: plan.componentId,
      status,
      startedAt: now,
      completedAt: now,
      durationMs: 0,
      exitCode: null,
      version: null,
      reason,
      logPath: null,
      findingCount: 0,
      discardedDuringParse: 0,
    },
  };
}

function createScanId(date: Date, commit: string | null): string {
  const revision = commit ? commit.slice(0, 8) : "nogit";
  return `${date.toISOString().replace(/[:.]/g, "-")}-${revision}`;
}

/**
 * Records HEAD and whether the worktree is dirty.
 *
 * A missing git binary, a non-commit HEAD, or a failed status command yields
 * null fields. Null is "not observed", not a claim that the tree is clean.
 */
export async function readRepositoryGit(repoPath: string): Promise<{
  commit: string | null;
  dirty: boolean | null;
}> {
  const commitResult = await runCommand("git", ["rev-parse", "HEAD"], {
    cwd: repoPath,
    timeoutMs: 10_000,
    env: allowedHostEnvironment(),
  }).catch(() => null);
  const commit = commitResult?.exitCode === 0 ? commitResult.stdout.trim().toLowerCase() : "";
  if (!/^[0-9a-f]{40}$/.test(commit)) return { commit: null, dirty: null };
  const status = await runCommand("git", ["status", "--porcelain"], {
    cwd: repoPath,
    timeoutMs: 10_000,
    env: allowedHostEnvironment(),
  }).catch(() => null);
  if (!status || status.exitCode !== 0) return { commit, dirty: null };
  return { commit, dirty: status.stdout.trim().length > 0 };
}

async function mapConcurrent<T, R>(
  values: T[],
  concurrency: number,
  worker: (value: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(values.length);
  let cursor = 0;
  async function consume(): Promise<void> {
    while (cursor < values.length) {
      const index = cursor;
      cursor += 1;
      const value = values[index];
      if (value !== undefined) results[index] = await worker(value);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, consume));
  return results;
}

async function copyRedactedRaw(source: string, destination: string): Promise<void> {
  await cp(source, destination, {
    recursive: true,
    filter: (entry) => !entry.endsWith(".json"),
  });
  const entries = await import("node:fs/promises").then((fs) =>
    fs.readdir(source, { withFileTypes: true }),
  );
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const content = await readFile(path.join(source, entry.name), "utf8");
    let redacted = redactSensitiveText(content);
    try {
      redacted = `${JSON.stringify(redactRawValue(JSON.parse(content) as unknown), null, 2)}\n`;
    } catch {
      // Keep regex-redacted text if the artifact is not valid JSON.
    }
    await writeFile(
      path.join(destination, entry.name),
      redacted,
      { mode: 0o600 },
    );
  }
}

function redactRawValue(value: unknown, key = ""): unknown {
  if (typeof value === "string") {
    if (/(match|secret|token|password|credential|authorization|api.?key|lines|code)/i.test(key)) {
      return "[REDACTED]";
    }
    return redactSensitiveText(value);
  }
  if (Array.isArray(value)) return value.map((entry) => redactRawValue(entry, key));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([nestedKey, nestedValue]) => [
        nestedKey,
        redactRawValue(nestedValue, nestedKey),
      ]),
    );
  }
  return value;
}

export async function cleanRawArtifacts(rawPath: string): Promise<void> {
  await rm(rawPath, { recursive: true, force: true });
}

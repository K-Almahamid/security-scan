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
import {
  deduplicateFindings,
  redactSensitiveText,
  severityAtOrAbove,
} from "./findings.js";
import { buildScanPlan } from "./planner.js";
import { assertRepositoryPath, profileRepository } from "./profile.js";
import {
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
  ScanManifest,
  ToolPlan,
  ToolRun,
} from "./types.js";

export interface ScanOptions {
  repo: string;
  configPath?: string;
  reportsDir?: string;
  offline?: boolean;
  jobs?: number;
  timeoutMs?: number;
  keepRaw?: boolean;
  failOn?: SecurityScanConfig["policy"]["failOn"];
}

export interface ScanOutcome {
  manifest: ScanManifest;
  findings: CanonicalFinding[];
  exitCode: number;
}

export async function runSecurityScan(options: ScanOptions): Promise<ScanOutcome> {
  const startedAt = new Date();
  const repoPath = await assertRepositoryPath(options.repo);
  const loaded = await loadConfig(repoPath, options.configPath);
  const config = applyOverrides(loaded, options);
  const profile = await profileRepository(repoPath, config, startedAt);
  const plan = buildScanPlan(profile, config);
  const scanId = await createScanId(repoPath, startedAt);
  const reportRoot = resolveReportsDirectory(
    repoPath,
    options.reportsDir ?? config.reportsDir,
  );
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
  };
  const adapters = createAdapters();
  const results = await mapConcurrent(
    plan.tools,
    Math.max(1, Math.min(options.jobs ?? 2, 8)),
    async (toolPlan): Promise<AdapterResult> => {
      const adapter = adapters.get(toolPlan.adapter);
      if (!adapter) return unavailableResult(toolPlan, "No adapter is registered", "unsupported");
      try {
        const reason = await adapter.checkPrerequisites(toolPlan, context);
        if (reason) {
          return unavailableResult(
            toolPlan,
            reason,
            toolPlan.required ? "failed" : "skipped",
          );
        }
        return await adapter.execute(toolPlan, context);
      } catch (error) {
        return unavailableResult(
          toolPlan,
          redactSensitiveText(error instanceof Error ? error.message : String(error)),
          "failed",
        );
      }
    },
  );
  const findings = deduplicateFindings(results.flatMap((result) => result.findings));
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
    rawArtifactsPath: rawDirectory,
    reportDirectory,
  };
  await writeReports({ reportDirectory, profile, plan, manifest, findings });

  if (options.keepRaw) {
    const destination = path.join(reportDirectory, "raw");
    await mkdir(destination, { recursive: true, mode: 0o700 });
    await copyRedactedRaw(rawDirectory, destination);
  }

  const threshold = options.failOn ?? config.policy.failOn;
  const exitCode =
    manifest.overallStatus === "incomplete"
      ? 2
      : findings.some((finding) => severityAtOrAbove(finding.severity, threshold))
        ? 1
        : 0;
  return { manifest, findings, exitCode };
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
    },
  };
}

async function createScanId(repoPath: string, date: Date): Promise<string> {
  const result = await runCommand("git", ["rev-parse", "--short=8", "HEAD"], {
    cwd: repoPath,
    timeoutMs: 10_000,
    env: allowedHostEnvironment(),
  }).catch(() => null);
  const revision = result?.exitCode === 0 ? result.stdout.trim() : "nogit";
  return `${date.toISOString().replace(/[:.]/g, "-")}-${revision || "nogit"}`;
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

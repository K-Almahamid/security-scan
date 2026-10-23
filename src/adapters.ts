import { access, readFile } from "node:fs/promises";
import path from "node:path";
import {
  allowedHostEnvironment,
  persistProcessLog,
  runCommand,
  runComposeTool,
} from "./execution.js";
import {
  createFinding,
  normalizePath,
  normalizeSeverity,
  redactSensitiveText,
} from "./findings.js";
import type {
  AdapterContext,
  CanonicalFinding,
  ToolAdapter,
  ToolPlan,
  ToolRun,
} from "./types.js";

export function createAdapters(): Map<ToolPlan["adapter"], ToolAdapter> {
  return new Map([
    ["trivy", trivyAdapter],
    ["semgrep", semgrepAdapter],
    ["dart-analyze", dartAnalyzeAdapter],
  ]);
}

const trivyAdapter: ToolAdapter = {
  id: "trivy",
  async checkPrerequisites(_plan, context) {
    return dockerPrerequisite(context);
  },
  async execute(plan, context) {
    const outputName = `${plan.id}.json`;
    const versionResult = await runComposeTool({
      composeFile: context.composeFile,
      service: "trivy",
      repoPath: context.repoPath,
      rawDirectory: context.rawDirectory,
      args: ["--version"],
      timeoutMs: Math.min(context.timeoutMs, 60_000),
    });
    const args = [
      "fs",
      "--format",
      "json",
      "--output",
      `/out/${outputName}`,
      "--scanners",
      "vuln,secret,misconfig",
    ];
    for (const excluded of context.exclude) args.push("--skip-dirs", excluded);
    if (context.offline) args.push("--skip-db-update", "--offline-scan");
    args.push("/src");
    const result = await runComposeTool({
      composeFile: context.composeFile,
      service: "trivy",
      repoPath: context.repoPath,
      rawDirectory: context.rawDirectory,
      args,
      timeoutMs: context.timeoutMs,
    });
    const logPath = await persistProcessLog(context.rawDirectory, plan.id, {
      ...result,
      stdout: redactSensitiveText(result.stdout, 100_000),
      stderr: redactSensitiveText(result.stderr, 100_000),
    });
    const findings =
      result.exitCode === 0
        ? parseTrivy(
            JSON.parse(await readFile(path.join(context.rawDirectory, outputName), "utf8")) as unknown,
            context.repoPath,
            plan.componentId,
          )
        : [];
    return {
      findings,
      run: completeRun(
        plan,
        result,
        findings,
        (versionResult.stdout || versionResult.stderr).trim() || null,
        logPath,
      ),
    };
  },
};

const semgrepAdapter: ToolAdapter = {
  id: "semgrep",
  async checkPrerequisites(plan, context) {
    const dockerError = await dockerPrerequisite(context);
    if (dockerError) return dockerError;
    if (context.offline && !plan.checks.includes("bundled-flutter-security")) {
      return "Semgrep registry rules are unavailable in offline mode";
    }
    return null;
  },
  async execute(plan, context) {
    const outputName = `${plan.id}.json`;
    const versionResult = await runComposeTool({
      composeFile: context.composeFile,
      service: "semgrep",
      repoPath: context.repoPath,
      rawDirectory: context.rawDirectory,
      args: ["semgrep", "--version"],
      timeoutMs: Math.min(context.timeoutMs, 60_000),
    });
    const args = ["semgrep", "scan", "--json", "--output", `/out/${outputName}`];
    for (const excluded of context.exclude) args.push("--exclude", excluded);
    if (!context.offline) args.push("--config", "p/default", "--config", "p/security-audit");
    if (plan.checks.includes("bundled-flutter-security")) {
      args.push("--config", "/rules/flutter-security.yml", "--config", "/rules/mobile-config.yml");
    }
    args.push(plan.targetPath === "." ? "/src" : `/src/${plan.targetPath}`);
    const result = await runComposeTool({
      composeFile: context.composeFile,
      service: "semgrep",
      repoPath: context.repoPath,
      rawDirectory: context.rawDirectory,
      args,
      timeoutMs: context.timeoutMs,
    });
    const logPath = await persistProcessLog(context.rawDirectory, plan.id, {
      ...result,
      stdout: redactSensitiveText(result.stdout, 100_000),
      stderr: redactSensitiveText(result.stderr, 100_000),
    });
    const findings =
      result.exitCode === 0
        ? parseSemgrep(
            JSON.parse(await readFile(path.join(context.rawDirectory, outputName), "utf8")) as unknown,
            context.repoPath,
            plan.componentId,
          )
        : [];
    return {
      findings,
      run: completeRun(
        plan,
        result,
        findings,
        (versionResult.stdout || versionResult.stderr).trim() || null,
        logPath,
      ),
    };
  },
};

const dartAnalyzeAdapter: ToolAdapter = {
  id: "dart-analyze",
  async checkPrerequisites(plan, context) {
    const target = path.resolve(context.repoPath, plan.targetPath);
    try {
      await access(path.join(target, ".dart_tool/package_config.json"));
    } catch {
      return "Existing .dart_tool/package_config.json not found; dependency installation is forbidden";
    }
    const version = await runCommand("dart", ["--version"], {
      cwd: target,
      timeoutMs: 15_000,
      env: allowedHostEnvironment(),
    }).catch(() => null);
    return version ? null : "Dart SDK is not available on PATH";
  },
  async execute(plan, context) {
    const target = path.resolve(context.repoPath, plan.targetPath);
    const versionResult = await runCommand("dart", ["--version"], {
      cwd: target,
      timeoutMs: 15_000,
      env: allowedHostEnvironment(),
    });
    const result = await runCommand("dart", ["analyze", "--format", "machine"], {
      cwd: target,
      timeoutMs: context.timeoutMs,
      env: allowedHostEnvironment({
        PUB_ENVIRONMENT: "security-scan",
      }),
    });
    const findings = parseDartAnalyze(result.stdout, context.repoPath, plan.componentId);
    const logPath = await persistProcessLog(context.rawDirectory, plan.id, {
      ...result,
      stdout: redactSensitiveText(result.stdout, 100_000),
      stderr: redactSensitiveText(result.stderr, 100_000),
    });
    const acceptedResult =
      result.exitCode !== 0 && findings.length > 0 ? { ...result, exitCode: 0 } : result;
    return {
      findings,
      run: completeRun(
        plan,
        acceptedResult,
        findings,
        (versionResult.stdout || versionResult.stderr).trim() || null,
        logPath,
      ),
    };
  },
};

async function dockerPrerequisite(context: AdapterContext): Promise<string | null> {
  const result = await runCommand("docker", ["compose", "version"], {
    cwd: context.repoPath,
    timeoutMs: 15_000,
    env: allowedHostEnvironment(),
  }).catch(() => null);
  return result?.exitCode === 0 ? null : "Docker Compose is unavailable";
}

function completeRun(
  plan: ToolPlan,
  result: { exitCode: number | null; timedOut: boolean; durationMs: number },
  findings: CanonicalFinding[],
  version: string | null,
  logPath: string,
): ToolRun {
  const completedAt = new Date();
  const startedAt = new Date(completedAt.getTime() - result.durationMs);
  const failed = result.exitCode !== 0 || result.timedOut;
  return {
    id: plan.id,
    adapter: plan.adapter,
    componentId: plan.componentId,
    status: failed ? "failed" : findings.length > 0 ? "findings" : "passed",
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: result.durationMs,
    exitCode: result.exitCode,
    version,
    reason: result.timedOut ? "Timed out" : failed ? `Exited with ${String(result.exitCode)}` : null,
    logPath,
    findingCount: findings.length,
  };
}

export function parseTrivy(
  input: unknown,
  repoPath: string,
  component: string | null,
): CanonicalFinding[] {
  if (!isRecord(input) || !Array.isArray(input.Results)) return [];
  const findings: CanonicalFinding[] = [];
  for (const result of input.Results) {
    if (!isRecord(result)) continue;
    const target = String(result.Target ?? "");
    for (const vuln of arrayOfRecords(result.Vulnerabilities)) {
      const vulnerabilityId = String(vuln.VulnerabilityID ?? "");
      const observedAt = new Date().toISOString();
      findings.push(
        createFinding({
          title: String(vuln.Title ?? (vulnerabilityId || "Dependency vulnerability")),
          description: String(vuln.Description ?? ""),
          severity: normalizeSeverity(vuln.Severity),
          category: "sca",
          confidence: "high",
          cve: vulnerabilityId ? [vulnerabilityId] : [],
          component,
          location: {
            path: normalizePath(repoPath, target),
            package: String(vuln.PkgName ?? ""),
            installedVersion: String(vuln.InstalledVersion ?? ""),
          },
          evidence: `${String(vuln.PkgName ?? "")} ${String(vuln.InstalledVersion ?? "")}`,
          source: { tool: "trivy", ruleId: vulnerabilityId || "vulnerability" },
          remediation: vuln.FixedVersion ? `Upgrade to ${String(vuln.FixedVersion)} or later.` : "",
          dependency: {
            advisorySource: String(
              vuln.PrimaryURL ??
              arrayOfStrings(vuln.References)[0] ??
              `trivy:${vulnerabilityId || "unknown"}`,
            ),
            advisoryCheckedAt: observedAt,
          },
          scannedAt: observedAt,
        }),
      );
    }
    for (const misconfiguration of arrayOfRecords(result.Misconfigurations)) {
      findings.push(
        createFinding({
          title: String(misconfiguration.Title ?? "Configuration issue"),
          description: String(misconfiguration.Description ?? ""),
          severity: normalizeSeverity(misconfiguration.Severity),
          category: "misconfiguration",
          component,
          location: {
            path: normalizePath(repoPath, target),
            startLine: numberOrUndefined(nested(misconfiguration, "CauseMetadata", "StartLine")),
            endLine: numberOrUndefined(nested(misconfiguration, "CauseMetadata", "EndLine")),
          },
          evidence: String(misconfiguration.Message ?? ""),
          source: { tool: "trivy", ruleId: String(misconfiguration.ID ?? "misconfiguration") },
          remediation: String(misconfiguration.Resolution ?? ""),
        }),
      );
    }
    for (const secret of arrayOfRecords(result.Secrets)) {
      findings.push(
        createFinding({
          title: String(secret.Title ?? "Potential secret"),
          description: "Potential credential material detected.",
          severity: normalizeSeverity(secret.Severity ?? "high"),
          category: "secret",
          confidence: "high",
          component,
          location: {
            path: normalizePath(repoPath, target),
            startLine: numberOrUndefined(secret.StartLine),
            endLine: numberOrUndefined(secret.EndLine),
          },
          evidence: String(
            secret.Match ?? nested(secret, "Code", "Lines", "0", "Content") ?? "",
          ),
          source: { tool: "trivy", ruleId: String(secret.RuleID ?? "secret") },
          remediation: "Revoke the exposed value, remove it from history, and use a secret store.",
        }),
      );
    }
  }
  return findings;
}

export function parseSemgrep(
  input: unknown,
  repoPath: string,
  component: string | null,
): CanonicalFinding[] {
  if (!isRecord(input) || !Array.isArray(input.results)) return [];
  return input.results.flatMap((entry): CanonicalFinding[] => {
    if (!isRecord(entry) || !isRecord(entry.extra)) return [];
    const ruleId = String(entry.check_id ?? "unknown");
    const candidatePath = normalizePath(repoPath, String(entry.path ?? ""));
    const startLine = numberOrUndefined(nested(entry, "start", "line"));
    const endLine = numberOrUndefined(nested(entry, "end", "line"));
    const metadata = isRecord(entry.extra.metadata) ? entry.extra.metadata : {};
    const cwe = Array.isArray(metadata.cwe)
      ? metadata.cwe.map(String)
      : metadata.cwe
        ? [String(metadata.cwe)]
        : [];
    return [
      createFinding({
        title: String(entry.extra.message ?? entry.check_id ?? "Semgrep finding"),
        description: String(entry.extra.message ?? ""),
        severity: normalizeSeverity(entry.extra.severity),
        category: "sast",
        confidence: normalizeConfidence(metadata.confidence),
        cwe,
        component,
        location: {
          path: candidatePath,
          startLine,
          endLine,
        },
        evidence: semgrepEvidence(
          entry.extra.lines,
          ruleId,
          candidatePath,
          startLine,
          endLine,
        ),
        source: { tool: "semgrep", ruleId },
        impact: String(metadata.impact ?? ""),
        remediation: String(metadata.fix ?? metadata.references ?? ""),
      }),
    ];
  });
}

export function parseDartAnalyze(
  stdout: string,
  repoPath: string,
  component: string | null,
): CanonicalFinding[] {
  return stdout.split(/\r?\n/).flatMap((line): CanonicalFinding[] => {
    if (!line.trim()) return [];
    const fields = line.split("|");
    if (fields.length < 8) return [];
    const [severity, , code, file, startLine, , , ...messageParts] = fields;
    if (!severity || !code || !file) return [];
    return [
      createFinding({
        title: messageParts.join("|") || code,
        description: messageParts.join("|"),
        severity: normalizeSeverity(severity),
        category: "quality",
        confidence: "high",
        component,
        location: {
          path: normalizePath(repoPath, file),
          startLine: numberOrUndefined(startLine),
        },
        evidence: code,
        source: { tool: "dart-analyze", ruleId: code },
        remediation: "Address the Dart analyzer diagnostic.",
      }),
    ];
  });
}

function normalizeConfidence(value: unknown): "high" | "medium" | "low" {
  const normalized = String(value ?? "").toLowerCase();
  if (normalized === "high") return "high";
  if (normalized === "low") return "low";
  return "medium";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function arrayOfRecords(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

function arrayOfStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function semgrepEvidence(
  value: unknown,
  ruleId: string,
  filePath: string,
  startLine: number | undefined,
  endLine: number | undefined,
): {
  text: string;
  kind: "code" | "unavailable";
  limitation?: string;
} {
  const raw = typeof value === "string" ? value.trim() : "";
  const unavailableReason =
    /^requires login$/i.test(raw)
      ? "Semgrep withheld the code excerpt because the configured rule requires authenticated access."
      : value !== undefined && value !== null && typeof value !== "string"
        ? "Semgrep returned malformed code evidence."
      : raw
        ? "Semgrep returned an unusable code excerpt."
        : "Semgrep did not provide a code excerpt.";
  if (raw && !/^requires login$/i.test(raw)) {
    return { text: raw, kind: "code" };
  }
  const lineRange = startLine
    ? `:${startLine}${endLine && endLine !== startLine ? `-${endLine}` : ""}`
    : "";
  return {
    text: `Rule ${ruleId} matched at ${filePath}${lineRange}; code excerpt unavailable.`,
    kind: "unavailable",
    limitation: unavailableReason,
  };
}

function nested(value: Record<string, unknown>, ...keys: string[]): unknown {
  let current: unknown = value;
  for (const key of keys) {
    if (!isRecord(current)) return undefined;
    current = current[key];
  }
  return current;
}

function numberOrUndefined(value: unknown): number | undefined {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

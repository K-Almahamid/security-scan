import { access, lstat, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  allowedHostEnvironment,
  DEFAULT_MAX_CAPTURE_BYTES,
  DART_ANALYZE_MAX_CAPTURE_BYTES,
  persistProcessLog,
  runCommand,
  runComposeTool,
  type ProcessResult,
} from "./execution.js";
import { UsageError } from "./errors.js";
import {
  createFinding,
  normalizePath,
  normalizeSeverity,
  redactSensitiveText,
} from "./findings.js";
import type {
  AdapterContext,
  AdapterResult,
  CanonicalFinding,
  ToolAdapter,
  ToolPlan,
  ToolRun,
  ToolStatus,
} from "./types.js";

export interface ScannerParse {
  findings: CanonicalFinding[];
  /** Candidate rows the parser examined, including rejected ones. */
  rawCount: number;
  /** Candidate rows that did not become a canonical finding. */
  discarded: number;
}

export interface ToolCompletion {
  status: Extract<ToolStatus, "passed" | "findings" | "failed">;
  findings: CanonicalFinding[];
  reason: string | null;
  exitCode: number | null;
}

const DART_PLUGIN_SKIP_REASON =
  "Dart analyzer plugins are declared in analysis_options.yaml or an included options file. Host analysis is skipped unless --allow-dart-plugins is set, because plugins execute on the host.";

const DART_PLUGIN_UNDETERMINED_REASON =
  "Dart analyzer plugin safety could not be determined from the include chain. Host analysis is skipped unless --allow-dart-plugins is set.";

const MAX_ANALYSIS_INCLUDE_DEPTH = 8;
const MAX_ANALYSIS_OPTIONS_BYTES = 262_144;

export type DartPluginAssessment = "safe" | "plugins" | "undetermined";

/** True when analysis_options.yaml asks the Dart analyzer to load plugins. */
export function analysisOptionsDeclarePlugins(source: string): boolean {
  const lines = source.split(/\r?\n/);
  let inAnalyzer = false;
  for (const line of lines) {
    const stripped = line.replace(/#.*$/, "");
    if (!stripped.trim()) continue;
    const indent = stripped.match(/^ */)?.[0].length ?? 0;
    const trimmed = stripped.trim();
    if (indent === 0 && /^plugins\s*:/.test(trimmed)) return true;
    if (indent === 0 && /^analyzer\s*:/.test(trimmed)) {
      inAnalyzer = true;
      if (/\bplugins\s*:/.test(trimmed)) return true;
      continue;
    }
    if (inAnalyzer && indent === 0) inAnalyzer = false;
    if (inAnalyzer && /^plugins\s*:/.test(trimmed)) return true;
  }
  return false;
}

export async function dartAnalyzerPluginSkipReason(
  repoPath: string,
  targetPath: string,
  allowPlugins: boolean | undefined,
): Promise<string | null> {
  if (allowPlugins) return null;
  const assessment = await assessDartAnalyzerPlugins(repoPath, targetPath);
  if (assessment === "plugins") return DART_PLUGIN_SKIP_REASON;
  if (assessment === "undetermined") return DART_PLUGIN_UNDETERMINED_REASON;
  return null;
}

/** Walk the nearest analysis options file and its include chain. */
export async function assessDartAnalyzerPlugins(
  repoPath: string,
  targetPath: string,
): Promise<DartPluginAssessment> {
  const root = await realpath(repoPath).catch(() => path.resolve(repoPath));
  const start = await nearestAnalysisOptionsPath(root, path.resolve(targetPath));
  if (start === "undetermined") return "undetermined";
  if (!start) return "safe";
  return walkAnalysisOptions(root, start, new Set(), 0);
}

async function nearestAnalysisOptionsPath(
  root: string,
  start: string,
): Promise<string | null | "undetermined"> {
  let cursor = start;
  for (;;) {
    const candidate = path.join(cursor, "analysis_options.yaml");
    try {
      const stat = await lstat(candidate);
      if (stat.isFile() || stat.isSymbolicLink()) {
        let real: string;
        try {
          real = await realpath(candidate);
        } catch {
          return "undetermined";
        }
        if (!(await pathStaysInside(root, real))) return "undetermined";
        return real;
      }
    } catch {
      // Keep walking toward the repository root.
    }
    if (cursor === root) return null;
    const parent = path.dirname(cursor);
    if (parent === cursor) return null;
    cursor = parent;
  }
}

async function walkAnalysisOptions(
  repoRoot: string,
  filePath: string,
  seen: Set<string>,
  depth: number,
): Promise<DartPluginAssessment> {
  if (depth > MAX_ANALYSIS_INCLUDE_DEPTH) return "undetermined";
  let real = filePath;
  try {
    real = await realpath(filePath);
  } catch {
    return "undetermined";
  }
  if (seen.has(real)) return "safe";
  seen.add(real);
  let text: string;
  try {
    const stat = await lstat(real);
    if (!stat.isFile() || stat.size > MAX_ANALYSIS_OPTIONS_BYTES) return "undetermined";
    text = await readFile(real, "utf8");
  } catch {
    return "undetermined";
  }
  if (analysisOptionsDeclarePlugins(text)) return "plugins";
  const include = parseTopLevelInclude(text);
  if (include === "unsupported") return "undetermined";
  if (include === "none") return "safe";
  const resolved = await resolveAnalysisInclude(repoRoot, real, include);
  if (!resolved) return "undetermined";
  return walkAnalysisOptions(repoRoot, resolved, seen, depth + 1);
}

/** Top-level `include:` only. A list, duplicate key, or unreadable value is unsupported. */
export function parseTopLevelInclude(source: string): "none" | "unsupported" | string {
  let found: string | null = null;
  for (const line of source.split(/\r?\n/)) {
    const stripped = line.replace(/#.*$/, "");
    if (!stripped.trim()) continue;
    const indent = stripped.match(/^ */)?.[0].length ?? 0;
    if (indent !== 0) continue;
    const trimmed = stripped.trim();
    if (!trimmed.startsWith("include")) continue;
    const match = /^include\s*:(.*)$/.exec(trimmed);
    if (!match) continue;
    const raw = match[1]?.trim() ?? "";
    if (!raw || raw.startsWith("|") || raw.startsWith(">") || raw.startsWith("[") || raw.startsWith("{")) {
      return "unsupported";
    }
    if (found !== null) return "unsupported";
    const unquoted = raw.replace(/^(['"])(.*)\1$/, "$2").trim();
    if (!unquoted) return "unsupported";
    found = unquoted;
  }
  return found ?? "none";
}

async function resolveAnalysisInclude(
  repoRoot: string,
  fromFile: string,
  spec: string,
): Promise<string | null> {
  if (spec.startsWith("package:")) return resolvePackageAnalysisInclude(repoRoot, fromFile, spec);
  const resolved = path.resolve(path.dirname(fromFile), spec);
  let real: string;
  try {
    real = await realpath(resolved);
  } catch {
    return null;
  }
  if (!(await pathStaysInside(repoRoot, real))) return null;
  return real;
}

async function resolvePackageAnalysisInclude(
  repoRoot: string,
  fromFile: string,
  spec: string,
): Promise<string | null> {
  const match = /^package:([^/]+)\/(.+)$/.exec(spec);
  if (!match) return null;
  const packageName = match[1] ?? "";
  const relativeFile = match[2] ?? "";
  if (!packageName || !relativeFile || relativeFile.split("/").includes("..")) return null;
  const configPath = await nearestPackageConfig(repoRoot, path.dirname(fromFile));
  if (!configPath) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(configPath, "utf8")) as unknown;
  } catch {
    return null;
  }
  const rootUri = packageRootUri(parsed, packageName);
  if (!rootUri) return null;
  const packageRoot = resolvePackageRoot(path.dirname(configPath), rootUri);
  if (!packageRoot) return null;
  let packageRootReal: string;
  try {
    packageRootReal = await realpath(packageRoot);
  } catch {
    return null;
  }
  const candidate = path.resolve(packageRootReal, relativeFile);
  let real: string;
  try {
    real = await realpath(candidate);
  } catch {
    return null;
  }
  if (!(await pathStaysInside(packageRootReal, real))) return null;
  return real;
}

async function nearestPackageConfig(repoRoot: string, start: string): Promise<string | null> {
  let cursor = start;
  for (;;) {
    const candidate = path.join(cursor, ".dart_tool", "package_config.json");
    try {
      const real = await realpath(candidate);
      if (await pathStaysInside(repoRoot, real)) return real;
      return null;
    } catch {
      // Walk up.
    }
    if (cursor === repoRoot) return null;
    const parent = path.dirname(cursor);
    if (parent === cursor) return null;
    cursor = parent;
  }
}

function resolvePackageRoot(configDirectory: string, rootUri: string): string | null {
  if (rootUri.startsWith("file:")) {
    try {
      return fileURLToPath(rootUri);
    } catch {
      return null;
    }
  }
  return path.resolve(configDirectory, rootUri);
}

function packageRootUri(config: unknown, packageName: string): string | null {
  if (!config || typeof config !== "object" || !("packages" in config)) return null;
  const packages = (config as { packages?: unknown }).packages;
  if (!Array.isArray(packages)) return null;
  for (const entry of packages) {
    if (!entry || typeof entry !== "object") continue;
    const record = entry as { name?: unknown; rootUri?: unknown };
    if (record.name === packageName && typeof record.rootUri === "string" && record.rootUri.trim()) {
      return record.rootUri;
    }
  }
  return null;
}

async function pathStaysInside(root: string, candidate: string): Promise<boolean> {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

export function finalizeToolExecution(input: {
  family: ToolPlan["adapter"];
  exitCode: number | null;
  timedOut: boolean;
  outputTruncated?: boolean;
  documentValid: boolean;
  documentError?: string;
  findings: CanonicalFinding[];
}): ToolCompletion {
  if (input.outputTruncated) {
    return {
      status: "failed",
      findings: [],
      reason: "Scanner output was truncated before it could be processed completely",
      exitCode: input.exitCode,
    };
  }
  if (input.timedOut) {
    return { status: "failed", findings: [], reason: "Timed out", exitCode: input.exitCode };
  }
  if (!input.documentValid) {
    return {
      status: "failed",
      findings: [],
      reason: input.documentError ?? "Scanner output did not match the expected document",
      exitCode: input.exitCode,
    };
  }
  const completed =
    input.family === "semgrep"
      ? input.exitCode === 0 || input.exitCode === 1
      : input.family === "dart-analyze"
        ? input.exitCode === 0 || (input.exitCode !== 0 && input.findings.length > 0)
        : input.exitCode === 0;
  if (!completed) {
    return {
      status: "failed",
      findings: [],
      reason: `Exited with ${String(input.exitCode)}`,
      exitCode: input.exitCode,
    };
  }
  if (input.family === "semgrep" && input.exitCode === 1 && input.findings.length === 0) {
    return {
      status: "failed",
      findings: [],
      reason: "Semgrep exited 1 but the JSON document contained no results",
      exitCode: input.exitCode,
    };
  }
  return {
    status: input.findings.length > 0 ? "findings" : "passed",
    findings: input.findings,
    reason: null,
    exitCode: input.exitCode,
  };
}

export function readTrivyDocument(input: unknown): { valid: boolean; error?: string } {
  if (!isRecord(input) || !Array.isArray(input.Results)) {
    return { valid: false, error: "Trivy JSON is missing a Results array" };
  }
  return { valid: true };
}

export interface SemgrepDocumentReadResult {
  valid: boolean;
  error?: string;
  incompleteScan?: boolean;
  scannerErrorSummary?: string;
}

export function readSemgrepDocument(input: unknown): SemgrepDocumentReadResult {
  if (!isRecord(input) || !Array.isArray(input.results)) {
    return { valid: false, error: "Semgrep JSON is missing a results array" };
  }
  const errors = Array.isArray(input.errors) ? input.errors : [];
  if (errors.length === 0) {
    return { valid: true };
  }
  const blocking = errors.filter((error) => isBlockingSemgrepError(error));
  const nonBlocking = errors.filter((error) => !isBlockingSemgrepError(error));
  if (blocking.length > 0) {
    return {
      valid: false,
      error: summarizeSemgrepErrors(blocking, "blocking"),
    };
  }
  return {
    valid: true,
    incompleteScan: true,
    scannerErrorSummary: summarizeSemgrepErrors(nonBlocking, "partial"),
  };
}

export function applySemgrepCompletionPolicy(
  completion: ToolCompletion,
  assessment: SemgrepDocumentReadResult,
): ToolCompletion {
  if (!assessment.incompleteScan || !assessment.scannerErrorSummary) {
    return completion;
  }
  return {
    status: "failed",
    findings: completion.findings,
    reason: assessment.scannerErrorSummary,
    exitCode: completion.exitCode,
  };
}

export function buildTrivyArgs(outputName: string, exclude: string[], offline: boolean): string[] {
  const args = [
    "fs",
    "--skip-version-check",
    "--format",
    "json",
    "--output",
    `/out/${safeOutputName(outputName)}`,
    "--scanners",
    "vuln,secret,misconfig",
  ];
  for (const excluded of exclude) args.push("--skip-dirs", excluded);
  if (offline) args.push("--skip-db-update", "--offline-scan");
  args.push("/src");
  return args;
}

export function buildSemgrepArgs(input: {
  outputName: string;
  exclude: string[];
  offline: boolean;
  checks: string[];
  targetPath: string;
  /** Container rules mount. Host runs pass the real rules directory. */
  rulesConfig?: string;
  /** When set, `targetPath` is already a host path and is not rewritten to `/src`. */
  hostTarget?: boolean;
  outputPath?: string;
}): string[] {
  const args = [
    "semgrep",
    "scan",
    "--metrics=off",
    "--disable-version-check",
    "--json",
    "--output",
    input.outputPath ?? `/out/${safeOutputName(input.outputName)}`,
  ];
  for (const excluded of input.exclude) args.push("--exclude", excluded);
  if (!input.offline) args.push("--config", "p/default", "--config", "p/security-audit");
  if (input.checks.includes("bundled-flutter-security")) {
    const rulesRoot = input.rulesConfig ?? "/rules";
    args.push("--config", `${rulesRoot}/flutter-security.yml`, "--config", `${rulesRoot}/mobile-config.yml`);
  } else if (input.offline) {
    args.push("--config", input.rulesConfig ?? "/rules");
  }
  args.push(input.hostTarget ? input.targetPath : containerSourcePath(input.targetPath));
  return args;
}

export function containerSourcePath(targetPath: string): string {
  if (targetPath === ".") return "/src";
  if (
    path.isAbsolute(targetPath) ||
    targetPath.split(/[\\/]/).includes("..") ||
    targetPath.startsWith("/")
  ) {
    throw new UsageError("Scanner target path escapes the repository");
  }
  return `/src/${targetPath.split(path.sep).join("/")}`;
}

function safeOutputName(name: string): string {
  if (!/^[A-Za-z0-9._-]+$/.test(name)) throw new UsageError("Unsafe scanner output name");
  return name;
}

export function createAdapters(): Map<ToolPlan["adapter"], ToolAdapter> {
  return new Map([
    ["trivy", trivyAdapter],
    ["semgrep", semgrepAdapter],
    ["dart-analyze", dartAnalyzeAdapter],
    ["gitleaks", gitleaksAdapter],
  ]);
}

export async function commandOnPath(
  command: string,
  cwd: string,
  args: string[] = ["--version"],
): Promise<boolean> {
  const result = await runCommand(command, args, {
    cwd,
    timeoutMs: 15_000,
    env: allowedHostEnvironment(),
  }).catch(() => null);
  return result?.exitCode === 0;
}

/** Pinned Compose is preferred. A host binary is used only when Compose is unavailable. */
export async function resolveScannerRuntime(
  context: AdapterContext,
  hostCommand: string,
): Promise<"docker" | "host" | "missing"> {
  if ((await dockerPrerequisite(context)) === null) return "docker";
  if (await commandOnPath(hostCommand, context.repoPath)) return "host";
  return "missing";
}

function noteUnpinnedHost(result: AdapterResult, command: string): AdapterResult {
  if (result.run.status !== "passed" && result.run.status !== "findings") return result;
  const note = `Ran host ${command} because Docker Compose was unavailable. This is not the pinned container image.`;
  result.run.reason = result.run.reason ? `${result.run.reason} ${note}` : note;
  return result;
}

const trivyAdapter: ToolAdapter = {
  id: "trivy",
  async checkPrerequisites(_plan, context) {
    const runtime = await resolveScannerRuntime(context, "trivy");
    return runtime === "missing"
      ? "Docker Compose is unavailable and trivy is not installed. The required scanner did not run."
      : null;
  },
  async execute(plan, context) {
    const runtime = await resolveScannerRuntime(context, "trivy");
    if (runtime === "host") return noteUnpinnedHost(await executeHostTrivy(plan, context), "trivy");
    const outputName = `${plan.id}.json`;
    const versionResult = await runComposeTool({
      composeFile: context.composeFile,
      service: "trivy",
      repoPath: context.repoPath,
      rawDirectory: context.rawDirectory,
      args: ["--version"],
      timeoutMs: Math.min(context.timeoutMs, 60_000),
    });
    const result = await runComposeTool({
      composeFile: context.composeFile,
      service: "trivy",
      repoPath: context.repoPath,
      rawDirectory: context.rawDirectory,
      args: buildTrivyArgs(outputName, context.exclude, context.offline),
      timeoutMs: context.timeoutMs,
    });
    return finishJsonTool({
      plan,
      context,
      outputName,
      result,
      version: (versionResult.stdout || versionResult.stderr).trim() || null,
      family: "trivy",
      readDocument: readTrivyDocument,
      parse: (document) => parseTrivyDocument(document, context.repoPath, plan.componentId),
    });
  },
};

const semgrepAdapter: ToolAdapter = {
  id: "semgrep",
  async checkPrerequisites(_plan, context) {
    const runtime = await resolveScannerRuntime(context, "semgrep");
    return runtime === "missing"
      ? "Docker Compose is unavailable and semgrep is not installed. The required scanner did not run."
      : null;
  },
  async execute(plan, context) {
    const runtime = await resolveScannerRuntime(context, "semgrep");
    if (runtime === "host") return noteUnpinnedHost(await executeHostSemgrep(plan, context), "semgrep");
    const outputName = `${plan.id}.json`;
    const versionResult = await runComposeTool({
      composeFile: context.composeFile,
      service: "semgrep",
      repoPath: context.repoPath,
      rawDirectory: context.rawDirectory,
      args: ["semgrep", "--version"],
      timeoutMs: Math.min(context.timeoutMs, 60_000),
    });
    const result = await runComposeTool({
      composeFile: context.composeFile,
      service: "semgrep",
      repoPath: context.repoPath,
      rawDirectory: context.rawDirectory,
      args: buildSemgrepArgs({
        outputName,
        exclude: context.exclude,
        offline: context.offline,
        checks: plan.checks,
        targetPath: plan.targetPath,
      }),
      timeoutMs: context.timeoutMs,
    });
    const finished = await finishJsonTool({
      plan,
      context,
      outputName,
      result,
      version: (versionResult.stdout || versionResult.stderr).trim() || null,
      family: "semgrep",
      readDocument: readSemgrepDocument,
      parse: (document) => parseSemgrepDocument(document, context.repoPath, plan.componentId),
    });
    if (context.offline && !finished.run.reason) {
      finished.run.reason =
        "Offline mode used bundled Semgrep rules only. Registry packs p/default and p/security-audit were not loaded.";
    }
    return finished;
  },
};

async function executeHostTrivy(plan: ToolPlan, context: AdapterContext): Promise<AdapterResult> {
  const outputName = `${plan.id}.json`;
  const outputPath = path.join(context.rawDirectory, outputName);
  const versionResult = await runCommand("trivy", ["--version"], {
    cwd: context.repoPath,
    timeoutMs: Math.min(context.timeoutMs, 60_000),
    env: allowedHostEnvironment(),
  });
  const args = buildTrivyArgs(outputName, context.exclude, context.offline).map((argument) =>
    argument === `/out/${outputName}` ? outputPath : argument === "/src" ? context.repoPath : argument,
  );
  const result = await runCommand("trivy", args, {
    cwd: context.repoPath,
    timeoutMs: context.timeoutMs,
    env: allowedHostEnvironment(),
  });
  return finishJsonTool({
    plan,
    context,
    outputName,
    result,
    version: (versionResult.stdout || versionResult.stderr).trim() || null,
    family: "trivy",
    readDocument: readTrivyDocument,
    parse: (document) => parseTrivyDocument(document, context.repoPath, plan.componentId),
  });
}

async function executeHostSemgrep(plan: ToolPlan, context: AdapterContext): Promise<AdapterResult> {
  const outputName = `${plan.id}.json`;
  const outputPath = path.join(context.rawDirectory, outputName);
  const rulesConfig = path.resolve(path.dirname(context.composeFile), "../rules/semgrep");
  const versionResult = await runCommand("semgrep", ["--version"], {
    cwd: context.repoPath,
    timeoutMs: Math.min(context.timeoutMs, 60_000),
    env: allowedHostEnvironment(),
  });
  const target = path.resolve(context.repoPath, plan.targetPath);
  const result = await runCommand(
    "semgrep",
    buildSemgrepArgs({
      outputName,
      outputPath,
      exclude: context.exclude,
      offline: context.offline,
      checks: plan.checks,
      targetPath: target,
      hostTarget: true,
      rulesConfig,
    }).slice(1),
    {
      cwd: context.repoPath,
      timeoutMs: context.timeoutMs,
      env: allowedHostEnvironment(),
    },
  );
  const finished = await finishJsonTool({
    plan,
    context,
    outputName,
    result,
    version: (versionResult.stdout || versionResult.stderr).trim() || null,
    family: "semgrep",
    readDocument: readSemgrepDocument,
    parse: (document) => parseSemgrepDocument(document, context.repoPath, plan.componentId),
  });
  if (context.offline && !finished.run.reason) {
    finished.run.reason =
      "Offline mode used bundled Semgrep rules only. Registry packs p/default and p/security-audit were not loaded.";
  }
  return finished;
}

const gitleaksAdapter: ToolAdapter = {
  id: "gitleaks",
  async checkPrerequisites(_plan, context) {
    const git = await runCommand("git", ["rev-parse", "--is-inside-work-tree"], {
      cwd: context.repoPath,
      timeoutMs: 10_000,
      env: allowedHostEnvironment(),
    }).catch(() => null);
    if (git?.exitCode !== 0) return "Not a Git repository; history secret scan was skipped";
    if (!(await commandOnPath("gitleaks", context.repoPath, ["version"]))) {
      return "gitleaks is not installed. The scanner does not download it.";
    }
    return null;
  },
  async execute(plan, context) {
    const outputName = `${plan.id}.json`;
    const outputPath = path.join(context.rawDirectory, outputName);
    const versionResult = await runCommand("gitleaks", ["version"], {
      cwd: context.repoPath,
      timeoutMs: 15_000,
      env: allowedHostEnvironment(),
    }).catch(() => null);
    const result = await runCommand(
      "gitleaks",
      [
        "detect",
        "--no-banner",
        "--redact",
        "--exit-code",
        "0",
        "--report-format",
        "json",
        "--report-path",
        outputPath,
        "--source",
        context.repoPath,
      ],
      {
        cwd: context.repoPath,
        timeoutMs: context.timeoutMs,
        env: allowedHostEnvironment(),
      },
    );
    try {
      await access(outputPath);
    } catch {
      if (result.exitCode === 0) await writeFile(outputPath, "[]\n", { mode: 0o600 });
    }
    return finishJsonTool({
      plan,
      context,
      outputName,
      result,
      version: (versionResult?.stdout || versionResult?.stderr || "").trim() || null,
      family: "gitleaks",
      readDocument: (value) =>
        Array.isArray(value) ? { valid: true } : { valid: false, error: "Gitleaks report was not a JSON array" },
      parse: (document) => parseGitleaksDocument(document, context.repoPath),
    });
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
    const pluginSkip = await dartAnalyzerPluginSkipReason(
      context.repoPath,
      target,
      context.allowDartPlugins,
    );
    if (pluginSkip) return pluginSkip;
    const version = await runCommand("dart", ["--version"], {
      cwd: target,
      timeoutMs: 15_000,
      env: allowedHostEnvironment(),
    }).catch(() => null);
    return version ? null : "Dart SDK is not available on PATH";
  },
  async execute(plan, context) {
    const target = path.resolve(context.repoPath, plan.targetPath);
    const pluginSkip = await dartAnalyzerPluginSkipReason(
      context.repoPath,
      target,
      context.allowDartPlugins,
    );
    if (pluginSkip) {
      return unavailableDartRun(plan, pluginSkip);
    }
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
      maxStdoutBytes: DART_ANALYZE_MAX_CAPTURE_BYTES,
      maxStderrBytes: DEFAULT_MAX_CAPTURE_BYTES,
    });
    const parsedRows = parseDartAnalyzeDocument(result.stdout, context.repoPath, plan.componentId);
    const logPath = await persistProcessLog(context.rawDirectory, plan.id, {
      ...result,
      stdout: redactSensitiveText(result.stdout, 100_000),
      stderr: redactSensitiveText(result.stderr, 100_000),
    });
    const completion = finalizeToolExecution({
      family: "dart-analyze",
      exitCode: result.exitCode,
      timedOut: result.timedOut,
      outputTruncated: result.stdoutTruncated || result.stderrTruncated,
      documentValid: true,
      findings: parsedRows.findings,
    });
    const adapterResult = finishRun(
      plan,
      result,
      completion,
      (versionResult.stdout || versionResult.stderr).trim() || null,
      logPath,
    );
    adapterResult.run.discardedDuringParse =
      completion.findings === parsedRows.findings ? parsedRows.discarded : 0;
    return adapterResult;
  },
};

function unavailableDartRun(plan: ToolPlan, reason: string): AdapterResult {
  const now = new Date().toISOString();
  return {
    findings: [],
    run: {
      id: plan.id,
      adapter: plan.adapter,
      componentId: plan.componentId,
      status: "skipped",
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

async function dockerPrerequisite(context: AdapterContext): Promise<string | null> {
  const result = await runCommand("docker", ["compose", "version"], {
    cwd: context.repoPath,
    timeoutMs: 15_000,
    env: allowedHostEnvironment(),
  }).catch(() => null);
  return result?.exitCode === 0 ? null : "Docker Compose is unavailable";
}

async function finishJsonTool(input: {
  plan: ToolPlan;
  context: AdapterContext;
  outputName: string;
  result: ProcessResult;
  version: string | null;
  family: ToolPlan["adapter"];
  readDocument: (value: unknown) => { valid: boolean; error?: string };
  parse: (value: unknown) => ScannerParse;
}): Promise<AdapterResult> {
  const logPath = await persistProcessLog(input.context.rawDirectory, input.plan.id, {
    ...input.result,
    stdout: redactSensitiveText(input.result.stdout, 100_000),
    stderr: redactSensitiveText(input.result.stderr, 100_000),
  });
  const document = await readJsonOutput(input.context.rawDirectory, input.outputName);
  const parsed = document.ok
    ? input.readDocument(document.value)
    : { valid: false, error: document.error };
  const parsedRows =
    document.ok && parsed.valid
      ? input.parse(document.value)
      : { findings: [], rawCount: 0, discarded: 0 };
  const composeOutputTruncated =
    input.result.stdoutTruncated || input.result.stderrTruncated;
  let completion = finalizeToolExecution({
    family: input.family,
    exitCode: input.result.exitCode,
    timedOut: input.result.timedOut,
    outputTruncated: composeOutputTruncated && !parsed.valid,
    documentValid: parsed.valid,
    ...(parsed.error ? { documentError: parsed.error } : {}),
    findings: parsedRows.findings,
  });
  if (input.family === "semgrep") {
    completion = applySemgrepCompletionPolicy(completion, parsed);
  }
  const adapterResult = finishRun(input.plan, input.result, completion, input.version, logPath);
  adapterResult.run.discardedDuringParse =
    completion.findings === parsedRows.findings ? parsedRows.discarded : 0;
  return adapterResult;
}

async function readJsonOutput(
  rawDirectory: string,
  outputName: string,
): Promise<{ ok: true; value: unknown } | { ok: false; error: string }> {
  try {
    return {
      ok: true,
      value: JSON.parse(await readFile(path.join(rawDirectory, outputName), "utf8")) as unknown,
    };
  } catch {
    return { ok: false, error: "Scanner output is missing or is not valid JSON" };
  }
}

function finishRun(
  plan: ToolPlan,
  result: ProcessResult,
  completion: ToolCompletion,
  version: string | null,
  logPath: string,
): AdapterResult {
  const completedAt = new Date();
  const startedAt = new Date(completedAt.getTime() - result.durationMs);
  const run: ToolRun = {
    id: plan.id,
    adapter: plan.adapter,
    componentId: plan.componentId,
    status: completion.status,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: result.durationMs,
    exitCode: result.exitCode,
    version,
    reason: completion.reason,
    logPath,
    findingCount: completion.findings.length,
    discardedDuringParse: 0,
  };
  return { findings: completion.findings, run };
}

export function parseTrivy(
  input: unknown,
  repoPath: string,
  component: string | null,
): CanonicalFinding[] {
  return parseTrivyDocument(input, repoPath, component).findings;
}

export function parseTrivyDocument(
  input: unknown,
  repoPath: string,
  component: string | null,
): ScannerParse {
  if (!isRecord(input) || !Array.isArray(input.Results)) {
    return { findings: [], rawCount: 0, discarded: 0 };
  }
  const findings: CanonicalFinding[] = [];
  let rawCount = 0;
  let discarded = 0;
  for (const result of input.Results) {
    if (!isRecord(result)) {
      rawCount += 1;
      discarded += 1;
      continue;
    }
    const target = String(result.Target ?? "");
    const vulnerabilities = takeRecords(result.Vulnerabilities);
    const misconfigurations = takeRecords(result.Misconfigurations);
    const secrets = takeRecords(result.Secrets);
    rawCount += vulnerabilities.rawCount + misconfigurations.rawCount + secrets.rawCount;
    discarded += vulnerabilities.discarded + misconfigurations.discarded + secrets.discarded;
    for (const vuln of vulnerabilities.records) {
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
    for (const misconfiguration of misconfigurations.records) {
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
    for (const secret of secrets.records) {
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
  return { findings, rawCount, discarded };
}

export function parseSemgrep(
  input: unknown,
  repoPath: string,
  component: string | null,
): CanonicalFinding[] {
  return parseSemgrepDocument(input, repoPath, component).findings;
}

export function parseSemgrepDocument(
  input: unknown,
  repoPath: string,
  component: string | null,
): ScannerParse {
  if (!isRecord(input) || !Array.isArray(input.results)) {
    return { findings: [], rawCount: 0, discarded: 0 };
  }
  const findings: CanonicalFinding[] = [];
  let discarded = 0;
  for (const entry of input.results) {
    if (!isRecord(entry) || !isRecord(entry.extra)) {
      discarded += 1;
      continue;
    }
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
    findings.push(
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
    );
  }
  return { findings, rawCount: input.results.length, discarded };
}

export function parseGitleaksDocument(document: unknown, repoPath: string): ScannerParse {
  if (!Array.isArray(document)) return { findings: [], rawCount: 0, discarded: 1 };
  const findings: CanonicalFinding[] = [];
  let discarded = 0;
  for (const row of document) {
    if (!row || typeof row !== "object") {
      discarded += 1;
      continue;
    }
    const record = row as Record<string, unknown>;
    const file = typeof record.File === "string" ? record.File : "";
    const ruleId = typeof record.RuleID === "string" && record.RuleID ? record.RuleID : "gitleaks";
    if (!file) {
      discarded += 1;
      continue;
    }
    const startLine = typeof record.StartLine === "number" ? record.StartLine : undefined;
    findings.push(
      createFinding({
        title: `Possible secret matched ${ruleId}`,
        description:
          typeof record.Description === "string"
            ? record.Description
            : "Gitleaks matched a secret in git history. The matched value is not stored.",
        severity: "high",
        category: "secret",
        confidence: "medium",
        component: null,
        location: {
          path: normalizePath(repoPath, file),
          ...(startLine && startLine > 0 ? { startLine } : {}),
        },
        evidence: {
          text: "Secret value redacted. The match is omitted from this report.",
          kind: "redacted",
        },
        source: { tool: "gitleaks", ruleId },
      }),
    );
  }
  return { findings, rawCount: document.length, discarded };
}

export function parseDartAnalyze(
  stdout: string,
  repoPath: string,
  component: string | null,
): CanonicalFinding[] {
  return parseDartAnalyzeDocument(stdout, repoPath, component).findings;
}

export function parseDartAnalyzeDocument(
  stdout: string,
  repoPath: string,
  component: string | null,
): ScannerParse {
  const findings: CanonicalFinding[] = [];
  let rawCount = 0;
  let discarded = 0;
  for (const line of stdout.split(/\r?\n/)) {
    if (!line.trim()) continue;
    rawCount += 1;
    const fields = line.split("|");
    if (fields.length < 8) {
      discarded += 1;
      continue;
    }
    const [severity, , code, file, startLine, , , ...messageParts] = fields;
    if (!severity || !code || !file) {
      discarded += 1;
      continue;
    }
    findings.push(
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
    );
  }
  return { findings, rawCount, discarded };
}

function normalizeConfidence(value: unknown): "high" | "medium" | "low" {
  const normalized = String(value ?? "").toLowerCase();
  if (normalized === "high") return "high";
  if (normalized === "low") return "low";
  return "medium";
}

function isBlockingSemgrepError(error: unknown): boolean {
  if (!isRecord(error)) return true;
  const level = typeof error.level === "string" ? error.level.toLowerCase() : "";
  if (level === "warn" || level === "info") return false;
  const type = error.type;
  if (Array.isArray(type) && typeof type[0] === "string") {
    if (type[0] === "PartialParsing") return false;
  }
  if (typeof type === "string" && type === "PartialParsing") return false;
  return true;
}

function summarizeSemgrepErrors(errors: unknown[], kind: "blocking" | "partial"): string {
  const summaries = errors
    .map((error) => summarizeSemgrepError(error))
    .filter((message): message is string => Boolean(message))
    .slice(0, 3);
  const remainder = errors.length > summaries.length
    ? ` (+${errors.length - summaries.length} more)`
    : "";
  const prefix =
    kind === "partial"
      ? "Semgrep completed with partial parsing coverage"
      : "Semgrep reported blocking scanner errors";
  if (summaries.length === 0) {
    return `${prefix} (${errors.length} error record(s))`;
  }
  return `${prefix}: ${summaries.join("; ")}${remainder}`;
}

function summarizeSemgrepError(error: unknown): string | null {
  if (!isRecord(error)) return null;
  const message = typeof error.message === "string" ? error.message.trim() : "";
  if (message) {
    const firstLine = message.split("\n")[0]?.trim() ?? message;
    return firstLine.length > 180 ? `${firstLine.slice(0, 177)}...` : firstLine;
  }
  const type = error.type;
  if (Array.isArray(type) && typeof type[0] === "string") {
    return type[0];
  }
  if (typeof type === "string") return type;
  return "scanner error";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function takeRecords(value: unknown): {
  records: Record<string, unknown>[];
  rawCount: number;
  discarded: number;
} {
  if (!Array.isArray(value)) return { records: [], rawCount: 0, discarded: 0 };
  const records: Record<string, unknown>[] = [];
  let discarded = 0;
  for (const entry of value) {
    if (isRecord(entry)) records.push(entry);
    else discarded += 1;
  }
  return { records, rawCount: value.length, discarded };
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

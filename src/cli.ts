#!/usr/bin/env node

import path from "node:path";
import { loadConfig } from "./config.js";
import { UsageError } from "./errors.js";
import { buildScanPlan } from "./planner.js";
import {
  assertPathInsideRepository,
  assertRepositoryPath,
  profileRepository,
} from "./profile.js";
import { runSecurityScan } from "./scanner.js";
import { attachSourceAuditToReport } from "./source-audit/attach.js";
import {
  importCloudflareFindings,
  parseCloudflareFindings,
} from "./source-audit/import.js";
import { validateCloudflareFindingsFile } from "./source-audit/validate.js";
import type { Severity } from "./types.js";
import { readFile } from "node:fs/promises";
import { CLI_VERSION, doctorExitCode, renderDoctorSummary, runDoctor } from "./doctor.js";
import { assessWorkflowFromReport, workflowAssessExitCode } from "./workflow-assess.js";
import {
  registerCloudflareAgentOutcome,
  updateWorkflowRun,
  WORKFLOW_RUN_FILENAME,
} from "./workflow-run.js";
import type { CloudflareAuditPhase, WorkflowRequest } from "./workflow.js";
import { CLOUDFLARE_AUDIT_PHASES } from "./workflow.js";

const VERSION = CLI_VERSION;

async function main(argv: string[]): Promise<number> {
  const [command, ...args] = argv;
  if (!command || command === "help" || command === "--help") {
    printHelp();
    return 0;
  }
  if (command === "version" || command === "--version") {
    console.log(VERSION);
    return 0;
  }
  if (command === "doctor") {
    const options = parseArgs(args);
    if (!options.repo) throw new CliError("--repo is required", 3);
    const workflowRequest = parseWorkflowRequest(options.workflow);
    const report = await runDoctor({
      repo: options.repo,
      workflowRequest,
      ...(options.config ? { configPath: options.config } : {}),
    });
    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(renderDoctorSummary(report));
    }
    return doctorExitCode(report);
  }
  if (command === "workflow") {
    const workflowCommand = args[0];
    const workflowArgs = args.slice(1);
    if (workflowCommand === "assess") {
      const options = parseWorkflowAssessArgs(workflowArgs);
      if (!options.repo) throw new CliError("--repo is required", 3);
      if (!options.scanDir) throw new CliError("--scan-dir is required", 3);
      const result = await assessWorkflowFromReport({
        repo: options.repo,
        scanDir: options.scanDir,
        ...(options.workflow ? { request: options.workflow } : {}),
      });
      const exitCode = workflowAssessExitCode(
        result.assessment,
        result.deterministicExitCode,
        result.inconsistencies,
        result.assessment.request,
      );
      const payload = {
        assessment: result.assessment,
        inconsistencies: result.inconsistencies,
        summary: result.summary,
        reportDirectory: result.reportDirectory,
        workflowRun: result.workflowRun ? WORKFLOW_RUN_FILENAME : null,
        deterministicExitCode: result.deterministicExitCode,
        exitCode,
      };
      if (options.json) {
        console.log(JSON.stringify(payload, null, 2));
      } else {
        console.log(result.summary);
        if (result.inconsistencies.length > 0) {
          console.error(`Inconsistencies:\n- ${result.inconsistencies.join("\n- ")}`);
        }
      }
      return exitCode;
    }
    if (workflowCommand === "register-cloudflare") {
      const options = parseWorkflowRegisterArgs(workflowArgs);
      if (!options.repo) throw new CliError("--repo is required", 3);
      if (!options.scanDir) throw new CliError("--scan-dir is required", 3);
      const repo = await assertRepositoryPath(options.repo);
      const reportDirectory = await assertPathInsideRepository(
        repo,
        path.isAbsolute(options.scanDir) ? options.scanDir : options.scanDir,
      );
      if (!options.status) throw new CliError("--status is required", 3);
      const registration = {
        skillInstalled: options.skillInstalled ?? false,
        delegationAvailable: options.delegationAvailable ?? false,
        sandboxAvailable: options.sandboxAvailable ?? false,
        invoked: options.invoked ?? false,
        phasesCompleted: options.phasesCompleted ?? [],
        findingsPath: options.findingsPath ?? null,
        status: options.status,
        ...(options.failureReason ? { failureReason: options.failureReason } : {}),
      };
      await updateWorkflowRun(reportDirectory, (current) =>
        registerCloudflareAgentOutcome(current, registration),
      );
      console.log(
        JSON.stringify(
          {
            status: "registered",
            step: "cloudflare-source-audit",
            reportDirectory,
          },
          null,
          2,
        ),
      );
      return 0;
    }
    throw new CliError(
      "Unknown workflow command. Use: workflow assess | workflow register-cloudflare",
      3,
    );
  }
  if (command === "audit") {
    const auditCommand = args[0];
    const auditOptions = parseAuditArgs(args.slice(1));
    if (!auditOptions.repo) throw new CliError("--repo is required", 3);
    const repo = await assertRepositoryPath(auditOptions.repo);
    if (auditCommand === "validate") {
      if (!auditOptions.findings) throw new CliError("--findings is required", 3);
      const result = await validateCloudflareFindingsFile(auditOptions.findings);
      if (!result.ok) {
        console.error(result.output || "Source audit findings validation failed");
        return 3;
      }
      console.log("Source audit findings are valid against the Cloudflare report schema.");
      return 0;
    }
    if (auditCommand === "import") {
      if (!auditOptions.findings) throw new CliError("--findings is required", 3);
      const validation = await validateCloudflareFindingsFile(auditOptions.findings);
      if (!validation.ok) {
        console.error(validation.output || "Source audit findings validation failed");
        return 3;
      }
      const raw = JSON.parse(await readFile(auditOptions.findings, "utf8")) as unknown;
      const imported = importCloudflareFindings(repo, parseCloudflareFindings(raw));
      console.log(
        JSON.stringify(
          {
            importable: imported.importable.length,
            rejected: imported.rejected.length,
            counts: imported.counts,
            findings: imported.importable,
          },
          null,
          2,
        ),
      );
      return 0;
    }
    if (auditCommand === "attach") {
      if (!auditOptions.scanDir) throw new CliError("--scan-dir is required", 3);
      if (!auditOptions.findings) throw new CliError("--findings is required", 3);
      const reportDirectory = path.isAbsolute(auditOptions.scanDir)
        ? auditOptions.scanDir
        : path.resolve(repo, auditOptions.scanDir);
      const result = await attachSourceAuditToReport({
        repoPath: repo,
        reportDirectory,
        sourceAuditFindingsPath: auditOptions.findings,
      });
      if (!result.ok) {
        console.error(result.message);
        return result.exitCode;
      }
      console.log(
        JSON.stringify(
          {
            status: "attached",
            findings: result.mergedFindings?.length ?? 0,
            reportDirectory,
          },
          null,
          2,
        ),
      );
      return result.exitCode;
    }
    throw new CliError(
      "Unknown audit command. Use: audit validate | audit import | audit attach",
      3,
    );
  }

  const options = parseArgs(args);
  if (!options.repo) throw new CliError("--repo is required", 3);
  const repo = await assertRepositoryPath(options.repo);

  if (command === "profile") {
    const config = await loadConfig(repo, options.config);
    const profile = await profileRepository(repo, config);
    const plan = buildScanPlan(profile, config);
    console.log(JSON.stringify({ profile, plan }, null, 2));
    return 0;
  }
  if (command === "validate-config") {
    await loadConfig(repo, options.config);
    console.log(`Configuration is valid for ${repo}`);
    return 0;
  }
  if (command === "scan") {
    if (options.mode && options.mode !== "standard") {
      throw new CliError("Only --mode standard is implemented in this release", 3);
    }
    const outcome = await runSecurityScan({
      repo,
      ...(options.config ? { configPath: options.config } : {}),
      ...(options.reportsDir ? { reportsDir: options.reportsDir } : {}),
      ...(options.offline ? { offline: true } : {}),
      ...(options.jobs ? { jobs: Number(options.jobs) } : {}),
      ...(options.timeout ? { timeoutMs: parseDuration(options.timeout) } : {}),
      ...(options.keepRaw ? { keepRaw: true } : {}),
      ...(options.failOn ? { failOn: options.failOn as Exclude<Severity, "unknown"> } : {}),
      workflowRequest: parseWorkflowRequest(options.workflow),
    });
    console.log(
      JSON.stringify(
        {
          scanId: outcome.manifest.scanId,
          status: outcome.manifest.overallStatus,
          findings: outcome.findings.length,
          report: `${outcome.manifest.reportDirectory}/report.md`,
          manifest: `${outcome.manifest.reportDirectory}/scan-manifest.json`,
          workflowRun: `${outcome.manifest.reportDirectory}/${WORKFLOW_RUN_FILENAME}`,
        },
        null,
        2,
      ),
    );
    return outcome.exitCode;
  }
  throw new CliError(`Unknown command: ${command}`, 3);
}

interface ParsedArgs {
  repo?: string;
  config?: string;
  mode?: string;
  workflow?: string;
  reportsDir?: string;
  offline?: boolean;
  jobs?: string;
  timeout?: string;
  keepRaw?: boolean;
  failOn?: string;
  json?: boolean;
}

function parseArgs(args: string[]): ParsedArgs {
  const parsed: ParsedArgs = {};
  const keys: Record<string, keyof ParsedArgs> = {
    "--repo": "repo",
    "--config": "config",
    "--mode": "mode",
    "--reports-dir": "reportsDir",
    "--jobs": "jobs",
    "--timeout": "timeout",
    "--fail-on": "failOn",
    "--workflow": "workflow",
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--offline") {
      parsed.offline = true;
      continue;
    }
    if (arg === "--keep-raw") {
      parsed.keepRaw = true;
      continue;
    }
    if (arg === "--json") {
      parsed.json = true;
      continue;
    }
    const key = arg ? keys[arg] : undefined;
    if (!key) throw new CliError(`Unknown option: ${String(arg)}`, 3);
    const value = args[index + 1];
    if (!value || value.startsWith("--")) {
      throw new CliError(`Missing value for ${String(arg)}`, 3);
    }
    parsed[key] = value as never;
    index += 1;
  }
  if (parsed.jobs && (!Number.isInteger(Number(parsed.jobs)) || Number(parsed.jobs) < 1)) {
    throw new CliError("--jobs must be a positive integer", 3);
  }
  if (
    parsed.failOn &&
    !["critical", "high", "medium", "low", "info"].includes(parsed.failOn)
  ) {
    throw new CliError("--fail-on must be critical, high, medium, low, or info", 3);
  }
  return parsed;
}

function parseDuration(value: string): number {
  const match = /^(\d+)(ms|s|m)?$/.exec(value);
  if (!match?.[1]) throw new CliError(`Invalid duration: ${value}`, 3);
  const amount = Number(match[1]);
  const unit = match[2] ?? "ms";
  return unit === "m" ? amount * 60_000 : unit === "s" ? amount * 1_000 : amount;
}

function printHelp(): void {
  console.log(`Security Scan ${VERSION}

Usage:
  security-scan doctor --repo <path> [--workflow full|deterministic-only] [--json]
  security-scan profile --repo <path> [--json]
  security-scan validate-config --repo <path>
  security-scan scan --repo <path> [--mode standard]
    [--workflow full|deterministic-only] [--config <path>] [--reports-dir <path>]
    [--offline] [--jobs <n>] [--timeout <20m>] [--keep-raw] [--fail-on <severity>]
  security-scan workflow assess --repo <path> --scan-dir <report-dir>
    [--workflow full|deterministic-only] [--json]
  security-scan workflow register-cloudflare --repo <path> --scan-dir <report-dir>
    --status completed|failed|skipped [--invoked true|false]
    [--skill-installed true|false] [--delegation-available true|false]
    [--sandbox-available true|false] [--phases <comma-separated>]
    [--findings <path>] [--failure-reason <text>]
  security-scan version

Source-level audit (validation and import only; the Cursor skill runs the Cloudflare hunt):
  security-scan audit validate --repo <path> --findings <cloudflare-findings.json>
  security-scan audit import --repo <path> --findings <cloudflare-findings.json>
  security-scan audit attach --repo <path> --scan-dir <report-dir> --findings <cloudflare-findings.json>

Exit codes:
  doctor: 0 ready, 1 full-audit optional gaps, 2 deterministic prerequisites missing
  workflow assess: 0 combined complete, 1 findings at/above threshold, 2 incomplete, 3 scope error`);
}

function parseWorkflowRequest(value?: string): WorkflowRequest {
  if (!value || value === "deterministic-only") return "deterministic-only";
  if (value === "full") return "full";
  throw new CliError("--workflow must be full or deterministic-only", 3);
}

interface ParsedWorkflowAssessArgs {
  repo?: string;
  scanDir?: string;
  workflow?: WorkflowRequest;
  json?: boolean;
}

function parseWorkflowAssessArgs(args: string[]): ParsedWorkflowAssessArgs {
  const parsed: ParsedWorkflowAssessArgs = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      parsed.json = true;
      continue;
    }
    if (arg === "--repo") {
      parsed.repo = readValue(args, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--scan-dir") {
      parsed.scanDir = readValue(args, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--workflow") {
      parsed.workflow = parseWorkflowRequest(readValue(args, index, arg));
      index += 1;
      continue;
    }
    throw new CliError(`Unknown workflow assess option: ${String(arg)}`, 3);
  }
  if (parsed.scanDir && (parsed.scanDir.includes("..") || parsed.scanDir.startsWith("~"))) {
    throw new CliError("Unsafe scan directory path", 3);
  }
  return parsed;
}

interface ParsedWorkflowRegisterArgs {
  repo?: string;
  scanDir?: string;
  status?: "completed" | "failed" | "skipped";
  invoked?: boolean;
  skillInstalled?: boolean;
  delegationAvailable?: boolean;
  sandboxAvailable?: boolean;
  phasesCompleted?: CloudflareAuditPhase[];
  findingsPath?: string | null;
  failureReason?: string | null;
}

function parseWorkflowRegisterArgs(args: string[]): ParsedWorkflowRegisterArgs {
  const parsed: ParsedWorkflowRegisterArgs = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--repo") {
      parsed.repo = readValue(args, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--scan-dir") {
      parsed.scanDir = readValue(args, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--status") {
      const value = readValue(args, index, arg);
      if (!["completed", "failed", "skipped"].includes(value)) {
        throw new CliError("--status must be completed, failed, or skipped", 3);
      }
      parsed.status = value as "completed" | "failed" | "skipped";
      index += 1;
      continue;
    }
    if (arg === "--invoked") {
      parsed.invoked = parseBooleanFlag(readValue(args, index, arg));
      index += 1;
      continue;
    }
    if (arg === "--skill-installed") {
      parsed.skillInstalled = parseBooleanFlag(readValue(args, index, arg));
      index += 1;
      continue;
    }
    if (arg === "--delegation-available") {
      parsed.delegationAvailable = parseBooleanFlag(readValue(args, index, arg));
      index += 1;
      continue;
    }
    if (arg === "--sandbox-available") {
      parsed.sandboxAvailable = parseBooleanFlag(readValue(args, index, arg));
      index += 1;
      continue;
    }
    if (arg === "--phases") {
      const phases = readValue(args, index, arg)
        .split(",")
        .map((phase) => phase.trim())
        .filter(Boolean);
      for (const phase of phases) {
        if (!CLOUDFLARE_AUDIT_PHASES.includes(phase as CloudflareAuditPhase)) {
          throw new CliError(`Unknown Cloudflare phase: ${phase}`, 3);
        }
      }
      parsed.phasesCompleted = phases as CloudflareAuditPhase[];
      index += 1;
      continue;
    }
    if (arg === "--findings") {
      parsed.findingsPath = readValue(args, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--failure-reason") {
      parsed.failureReason = readValue(args, index, arg);
      index += 1;
      continue;
    }
    throw new CliError(`Unknown workflow register option: ${String(arg)}`, 3);
  }
  if (parsed.scanDir && (parsed.scanDir.includes("..") || parsed.scanDir.startsWith("~"))) {
    throw new CliError("Unsafe scan directory path", 3);
  }
  if (parsed.findingsPath && (parsed.findingsPath.includes("..") || parsed.findingsPath.startsWith("~"))) {
    throw new CliError("Unsafe findings path", 3);
  }
  return parsed;
}

function readValue(args: string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new CliError(`Missing value for ${flag}`, 3);
  }
  return value;
}

function parseBooleanFlag(value: string): boolean {
  if (value === "true") return true;
  if (value === "false") return false;
  throw new CliError(`Expected true or false, received: ${value}`, 3);
}

interface ParsedAuditArgs {
  repo?: string;
  findings?: string;
  scanDir?: string;
}

function parseAuditArgs(args: string[]): ParsedAuditArgs {
  const parsed: ParsedAuditArgs = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--repo") {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) throw new CliError("Missing value for --repo", 3);
      parsed.repo = value;
      index += 1;
      continue;
    }
    if (arg === "--findings") {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) throw new CliError("Missing value for --findings", 3);
      parsed.findings = value;
      index += 1;
      continue;
    }
    if (arg === "--scan-dir") {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) throw new CliError("Missing value for --scan-dir", 3);
      parsed.scanDir = value;
      index += 1;
      continue;
    }
    throw new CliError(`Unknown audit option: ${String(arg)}`, 3);
  }
  for (const candidate of [parsed.findings, parsed.scanDir]) {
    if (candidate && (candidate.includes("..") || candidate.startsWith("~"))) {
      throw new CliError("Unsafe audit path", 3);
    }
  }
  return parsed;
}

class CliError extends Error {
  constructor(message: string, readonly exitCode: number) {
    super(message);
  }
}

main(process.argv.slice(2))
  .then((exitCode) => {
    process.exitCode = exitCode;
  })
  .catch((error: unknown) => {
    const exitCode =
      error instanceof CliError || error instanceof UsageError ? error.exitCode : 4;
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = exitCode;
  });

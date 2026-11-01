import { access } from "node:fs/promises";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildScanPlan } from "./planner.js";
import { loadConfig } from "./config.js";
import { allowedHostEnvironment, runCommand } from "./execution.js";
import { commandOnPath, dartAnalyzerPluginSkipReason } from "./adapters.js";
import { evaluateCapabilityReadiness } from "./registry.js";
import { assertRepositoryPath, profileRepository } from "./profile.js";
import { cloudflareSkillCandidates, type WorkflowRequest } from "./workflow.js";

/** Same version as package.json so `security-scan version` cannot drift from the package. */
export const CLI_VERSION = (
  createRequire(import.meta.url)("../package.json") as { version: string }
).version;

export interface DoctorCheck {
  id: string;
  category: "required" | "optional";
  status: "pass" | "fail" | "warn" | "skip";
  message: string;
}

export interface DoctorReport {
  version: string;
  nodeVersion: string;
  repositoryPath: string;
  workflowRequest: WorkflowRequest;
  ready: boolean;
  deterministicReady: boolean;
  fullAuditReady: boolean;
  checks: DoctorCheck[];
}

export async function runDoctor(input: {
  repo: string;
  workflowRequest: WorkflowRequest;
  configPath?: string;
}): Promise<DoctorReport> {
  const checks: DoctorCheck[] = [];
  const nodeVersion = process.version;
  const nodeMajor = Number(nodeVersion.slice(1).split(".")[0]);
  checks.push({
    id: "node-runtime",
    category: "required",
    status: Number.isFinite(nodeMajor) && nodeMajor >= 20 ? "pass" : "fail",
    message:
      Number.isFinite(nodeMajor) && nodeMajor >= 20
        ? `Node.js ${nodeVersion} meets the minimum (20+).`
        : `Node.js ${nodeVersion} is below the required major version 20.`,
  });

  const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const builtCli = path.join(packageRoot, "dist", "cli.js");
  try {
    await access(builtCli);
    checks.push({
      id: "cli-build",
      category: "required",
      status: "pass",
      message: "Built CLI entry point is present.",
    });
  } catch {
    checks.push({
      id: "cli-build",
      category: "required",
      status: "warn",
      message: "dist/cli.js is missing in the installation tree; ensure npm run build was executed.",
    });
  }

  let repoPath = "";
  try {
    repoPath = await assertRepositoryPath(input.repo);
    checks.push({
      id: "repository-path",
      category: "required",
      status: "pass",
      message: "Repository path is a readable directory.",
    });
  } catch (error) {
    checks.push({
      id: "repository-path",
      category: "required",
      status: "fail",
      message: error instanceof Error ? error.message : "Repository path is not usable.",
    });
    return summarize(checks, input.workflowRequest, repoPath || input.repo, nodeVersion);
  }

  const docker = await runCommand("docker", ["compose", "version"], {
    cwd: repoPath,
    timeoutMs: 15_000,
    env: allowedHostEnvironment(),
  }).catch(() => null);
  const trivyHost = await commandOnPath("trivy", repoPath);
  const semgrepHost = await commandOnPath("semgrep", repoPath);
  const gitleaksHost = await commandOnPath("gitleaks", repoPath, ["version"]);
  const dockerOk = docker?.exitCode === 0;
  checks.push({
    id: "docker-compose",
    category: "required",
    status: dockerOk ? "pass" : trivyHost && semgrepHost ? "warn" : "fail",
    message: dockerOk
      ? "Docker Compose is available. Trivy and Semgrep use the pinned images."
      : trivyHost && semgrepHost
        ? "Docker Compose is unavailable. Installed trivy and semgrep binaries will run instead, and the report records that they are not the pinned images."
        : "Docker Compose is unavailable and a required trivy or semgrep binary is not installed.",
  });

  const config = await loadConfig(repoPath, input.configPath);
  const profile = await profileRepository(repoPath, config);
  const plan = buildScanPlan(profile, config);
  if (plan.tools.length === 0) {
    checks.push({
      id: "scan-plan",
      category: "required",
      status: "fail",
      message: "No scanner was planned for this repository.",
    });
  } else {
    checks.push({
      id: "scan-plan",
      category: "required",
      status: "pass",
      message: `${plan.tools.length} tool run(s) planned for standard mode.`,
    });
  }

  const dart = await runCommand("dart", ["--version"], {
    cwd: repoPath,
    timeoutMs: 15_000,
    env: allowedHostEnvironment(),
  }).catch(() => null);
  const capabilityReadiness = evaluateCapabilityReadiness({
    profile,
    config,
    plan,
    prerequisites: {
      "docker-compose": dockerOk,
      "dart-sdk": dart?.exitCode === 0,
      gitleaks: gitleaksHost,
    },
    hostFallback: {
      trivy: trivyHost,
      semgrep: semgrepHost,
    },
  });
  for (const readiness of capabilityReadiness) {
    checks.push({
      id: `capability-${readiness.capabilityId}`,
      category: readiness.category,
      status: readiness.status,
      message: readiness.message,
    });
  }

  const pluginSkips = (
    await Promise.all(
      profile.components
        .filter((component) => component.languages.includes("dart"))
        .map((component) =>
          dartAnalyzerPluginSkipReason(
            repoPath,
            path.resolve(repoPath, component.path),
            false,
          ),
        ),
    )
  ).filter((reason): reason is string => Boolean(reason));
  if (pluginSkips.length > 0) {
    checks.push({
      id: "dart-analyzer-plugins",
      category: "optional",
      status: "warn",
      message:
        "analysis_options.yaml or an included options file declares Dart analyzer plugins, or the include chain could not be verified. The scan skips host dart analyze unless you pass --allow-dart-plugins.",
    });
  }

  const localSkill = path.join(homedir(), ".cursor", "skills", "security-scan", "SKILL.md");
  try {
    await access(localSkill);
    checks.push({
      id: "cursor-skill-security-scan",
      category: "optional",
      status: "pass",
      message: "The security-scan Cursor skill is installed locally.",
    });
  } catch {
    checks.push({
      id: "cursor-skill-security-scan",
      category: "optional",
      status: "warn",
      message:
        "The security-scan Cursor skill is not installed under ~/.cursor/skills; run scripts/sync-cursor-skills.sh.",
    });
  }

  const cloudflareCandidates = cloudflareSkillCandidates();
  let cloudflareInstalled = false;
  for (const candidate of cloudflareCandidates) {
    try {
      await access(candidate);
      cloudflareInstalled = true;
      break;
    } catch {
      // Try the next candidate path.
    }
  }
  checks.push({
    id: "cloudflare-security-audit-skill",
    category: input.workflowRequest === "full" ? "required" : "optional",
    status: cloudflareInstalled
      ? "pass"
      : input.workflowRequest === "full"
        ? "fail"
        : "warn",
    message: cloudflareInstalled
      ? "The upstream Cloudflare security-audit skill is installed."
      : input.workflowRequest === "full"
        ? "Full audit requires the upstream security-audit skill; it is not installed."
        : "The upstream security-audit skill is not installed (optional for deterministic-only scans).",
  });

  return summarize(checks, input.workflowRequest, repoPath, nodeVersion);
}

function summarize(
  checks: DoctorCheck[],
  workflowRequest: WorkflowRequest,
  repositoryPath: string,
  nodeVersion: string,
): DoctorReport {
  const fullFails = checks.some(
    (check) =>
      workflowRequest === "full" &&
      (check.id === "cloudflare-security-audit-skill" && check.status === "fail"),
  );
  const deterministicReady = !checks.some(
    (check) =>
      check.category === "required" &&
      check.status === "fail" &&
      check.id !== "cloudflare-security-audit-skill",
  );
  const fullAuditReady = deterministicReady && !fullFails;
  return {
    version: CLI_VERSION,
    nodeVersion,
    repositoryPath,
    workflowRequest,
    ready: workflowRequest === "full" ? fullAuditReady : deterministicReady,
    deterministicReady,
    fullAuditReady,
    checks,
  };
}

export function renderDoctorSummary(report: DoctorReport): string {
  const lines = [
    `Security Scan doctor ${report.version}`,
    `Repository: ${report.repositoryPath}`,
    `Workflow request: ${report.workflowRequest}`,
    `Deterministic scan ready: ${report.deterministicReady ? "yes" : "no"}`,
    `Full audit ready: ${report.fullAuditReady ? "yes" : "no"}`,
    "",
    ...report.checks.map(
      (check) =>
        `[${check.category}] ${check.id}: ${check.status} — ${check.message}`,
    ),
  ];
  return lines.join("\n");
}

export function doctorExitCode(report: DoctorReport): number {
  if (!report.deterministicReady) return 2;
  if (report.workflowRequest === "full" && !report.fullAuditReady) return 1;
  return 0;
}

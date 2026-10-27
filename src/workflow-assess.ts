import { readFile } from "node:fs/promises";
import path from "node:path";
import { UsageError, isEnoent } from "./errors.js";
import { assertPathInsideRepository, assertRepositoryPath } from "./profile.js";
import {
  finalizeWorkflowAssessmentStatus,
  loadWorkflowRun,
  updateWorkflowRun,
  type WorkflowRunRecord,
} from "./workflow-run.js";
import {
  assessSecurityWorkflow,
  cloudflareSkillCandidates,
  renderWorkflowSummary,
  type CloudflareRunState,
  type WorkflowAssessment,
  type WorkflowRequest,
} from "./workflow.js";
import type { CanonicalFinding, ScanManifest } from "./types.js";
import { access } from "node:fs/promises";
import { loadConfig } from "./config.js";
import { scanExitCode } from "./scanner.js";

export interface WorkflowAssessResult {
  assessment: WorkflowAssessment;
  workflowRun: WorkflowRunRecord | null;
  manifest: ScanManifest;
  summary: string;
  inconsistencies: string[];
  deterministicExitCode: number;
  reportDirectory: string;
}

export async function assessWorkflowFromReport(input: {
  repo: string;
  scanDir: string;
  request?: WorkflowRequest;
}): Promise<WorkflowAssessResult> {
  const repoPath = await assertRepositoryPath(input.repo);
  const reportDirectory = path.isAbsolute(input.scanDir)
    ? input.scanDir
    : path.resolve(repoPath, input.scanDir);
  await assertPathInsideRepository(repoPath, reportDirectory);

  const manifestPath = path.join(reportDirectory, "scan-manifest.json");
  let manifest: ScanManifest;
  try {
    manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ScanManifest;
  } catch (error) {
    if (isEnoent(error)) {
      throw new UsageError("scan-manifest.json is missing from the report directory");
    }
    throw error;
  }
  if (manifest.repositoryPath !== repoPath) {
    throw new UsageError("Report repositoryPath does not match --repo");
  }

  const workflowRun = await loadWorkflowRun(reportDirectory);
  const request = resolveWorkflowAssessRequest(workflowRun, input.request);
  const inconsistencies = collectInconsistencies(
    manifest,
    workflowRun,
    request,
    repoPath,
    reportDirectory,
  );
  const cloudflare = await buildCloudflareState(workflowRun, manifest, request);
  let assessment = assessSecurityWorkflow({
    request,
    deterministic: {
      status: manifest.overallStatus,
      toolRuns: manifest.toolRuns.map((run) => ({
        adapter: run.adapter,
        status: run.status,
      })),
    },
    ...(request === "full" ? { cloudflare } : {}),
  });
  if (hasMaterialInconsistencies(inconsistencies, request)) {
    assessment = applyIntegrityFailure(assessment, inconsistencies, request);
  }

  const findings = JSON.parse(
    await readFile(path.join(reportDirectory, "findings.json"), "utf8"),
  ) as CanonicalFinding[];
  const config = await loadConfig(repoPath);
  const deterministicExitCode = scanExitCode(
    manifest.overallStatus,
    findings,
    config.policy.failOn,
  );

  if (workflowRun) {
    await persistAssessmentOnWorkflowRun(reportDirectory, workflowRun, assessment);
  }

  return {
    assessment,
    workflowRun,
    manifest,
    summary: renderWorkflowSummary(assessment),
    inconsistencies,
    deterministicExitCode,
    reportDirectory,
  };
}

async function buildCloudflareState(
  workflowRun: WorkflowRunRecord | null,
  manifest: ScanManifest,
  request: WorkflowRequest,
): Promise<CloudflareRunState> {
  const skillInstalled = await cloudflareSkillInstalled();
  if (!workflowRun) {
    // Legacy reports: manifest may record attachment, but without workflow-run we cannot
    // treat agent phases as recorded or validated.
    const legacyAttached = Boolean(manifest.sourceAudit);
    const missingState: CloudflareRunState = {
      skillInstalled,
      delegationAvailable: false,
      sandboxAvailable: false,
      invoked: false,
      phasesCompleted: [],
      validation: legacyAttached ? "not_run" : "not_run",
      attached: legacyAttached,
    };
    if (request === "full") {
      missingState.failureReason =
        legacyAttached
          ? "workflow-run.json is missing; source-audit attachment cannot be treated as a completed full workflow."
          : "workflow-run.json is missing; agent phase completion was not recorded.";
    }
    return missingState;
  }
  const cloudflare = workflowRun.cloudflare;
  const delegationAvailable = cloudflare.delegationAvailable ?? false;
  return {
    skillInstalled: cloudflare.skillInstalled ?? skillInstalled,
    delegationAvailable,
    sandboxAvailable: cloudflare.sandboxAvailable ?? false,
    invoked: cloudflare.invoked,
    phasesCompleted: cloudflare.phasesCompleted,
    validation: cloudflare.validation,
    attached: cloudflare.attached,
    ...(cloudflare.failureReason ? { failureReason: cloudflare.failureReason } : {}),
  };
}

async function cloudflareSkillInstalled(): Promise<boolean> {
  for (const candidate of cloudflareSkillCandidates()) {
    try {
      await access(candidate);
      return true;
    } catch {
      // Continue.
    }
  }
  return false;
}

export function resolveWorkflowAssessRequest(
  workflowRun: WorkflowRunRecord | null,
  cliRequest?: WorkflowRequest,
): WorkflowRequest {
  if (workflowRun) {
    if (cliRequest && cliRequest !== workflowRun.request) {
      if (workflowRun.request === "full" && cliRequest === "deterministic-only") {
        throw new UsageError(
          "Cannot assess a full workflow report with --workflow deterministic-only; omit --workflow or use --workflow full",
        );
      }
    }
    return workflowRun.request;
  }
  return cliRequest ?? "deterministic-only";
}

export function hasMaterialInconsistencies(
  inconsistencies: string[],
  request: WorkflowRequest,
): boolean {
  if (inconsistencies.length === 0) return false;
  if (request === "full") return true;
  return inconsistencies.some((issue) => !issue.includes("workflow-run.json is missing"));
}

function inconsistencyExitCode(inconsistencies: string[]): number {
  const scopeErrors = inconsistencies.some(
    (issue) =>
      issue.includes("scanId does not match") ||
      issue.includes("repositoryPath does not match") ||
      issue.includes("reportDirectory does not match"),
  );
  return scopeErrors ? 3 : 2;
}

function applyIntegrityFailure(
  assessment: WorkflowAssessment,
  inconsistencies: string[],
  request: WorkflowRequest,
): WorkflowAssessment {
  const reasons = [
    ...assessment.reasons,
    ...inconsistencies.map((issue) => `Workflow integrity: ${issue}`),
  ];
  if (request !== "full") {
    return { ...assessment, reasons };
  }
  return {
    ...assessment,
    combinedStatus: "incomplete",
    cloudflareStatus:
      assessment.cloudflareStatus === "not_requested"
        ? assessment.cloudflareStatus
        : "incomplete",
    reasons,
  };
}

function collectInconsistencies(
  manifest: ScanManifest,
  workflowRun: WorkflowRunRecord | null,
  request: WorkflowRequest,
  repoPath: string,
  reportDirectory: string,
): string[] {
  const issues: string[] = [];
  if (!workflowRun) {
    if (request === "full") {
      issues.push("workflow-run.json is missing from the report directory.");
    }
    return issues;
  }
  if (workflowRun.scanId !== manifest.scanId) {
    issues.push("workflow-run scanId does not match scan-manifest.json.");
  }
  if (workflowRun.repositoryPath !== repoPath) {
    issues.push("workflow-run repositoryPath does not match --repo.");
  }
  if (
    manifest.reportDirectory &&
    path.resolve(manifest.reportDirectory) !== path.resolve(reportDirectory)
  ) {
    issues.push("scan-manifest reportDirectory does not match the assessed report directory.");
  }
  const deterministic = workflowRun.steps.find((step) => step.id === "standard-scan");
  if (deterministic && deterministic.status === "completed" && manifest.overallStatus === "incomplete") {
    issues.push("workflow-run marks the deterministic scan completed but the manifest is incomplete.");
  }
  if (manifest.sourceAudit && !workflowRun.cloudflare.attached) {
    issues.push("scan-manifest.json records a source audit attachment that workflow-run.json does not.");
  }
  return issues;
}

async function persistAssessmentOnWorkflowRun(
  reportDirectory: string,
  _workflowRun: WorkflowRunRecord,
  assessment: WorkflowAssessment,
): Promise<void> {
  await updateWorkflowRun(reportDirectory, (current) =>
    finalizeWorkflowAssessmentStatus(current, assessment.combinedStatus),
  );
}

export function workflowAssessExitCode(
  assessment: WorkflowAssessment,
  deterministicExitWouldBe: number,
  inconsistencies: string[] = [],
  request: WorkflowRequest = assessment.request,
): number {
  if (hasMaterialInconsistencies(inconsistencies, request)) {
    return inconsistencyExitCode(inconsistencies);
  }
  if (assessment.combinedStatus === "incomplete") return 2;
  if (deterministicExitWouldBe === 2) return 2;
  if (deterministicExitWouldBe === 3) return 3;
  return deterministicExitWouldBe;
}

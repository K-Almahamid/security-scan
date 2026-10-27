import { copyFile, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { isEnoent, UsageError } from "./errors.js";
import type { ScanManifest } from "./types.js";
import {
  CLOUDFLARE_AUDIT_PHASES,
  type CloudflareAuditPhase,
  type WorkflowRequest,
} from "./workflow.js";

export const WORKFLOW_RUN_FILENAME = "workflow-run.json";
export const WORKFLOW_RUN_SCHEMA_VERSION = 1;

export type WorkflowStepStatus = "pending" | "running" | "completed" | "failed" | "skipped";

export interface WorkflowRunStep {
  id: string;
  layer: "deterministic" | "cloudflare" | "attachment";
  required: boolean;
  requested: boolean;
  status: WorkflowStepStatus;
  startedAt: string | null;
  completedAt: string | null;
  executed: boolean;
  failureReason: string | null;
  artifacts: Record<string, string>;
}

export interface WorkflowRunRecord {
  schemaVersion: typeof WORKFLOW_RUN_SCHEMA_VERSION;
  revision: number;
  scanId: string;
  repositoryPath: string;
  request: WorkflowRequest;
  startedAt: string;
  completedAt: string | null;
  steps: WorkflowRunStep[];
  cloudflare: {
    skillInstalled: boolean | null;
    delegationAvailable: boolean | null;
    sandboxAvailable: boolean | null;
    invoked: boolean;
    phasesCompleted: CloudflareAuditPhase[];
    findingsPath: string | null;
    validation: "not_run" | "passed" | "failed";
    attached: boolean;
    failureReason: string | null;
  };
  assessmentStatus: "pending" | "complete" | "complete_with_findings" | "incomplete";
}

export function createInitialWorkflowRun(input: {
  scanId: string;
  repositoryPath: string;
  request: WorkflowRequest;
  startedAt: string;
}): WorkflowRunRecord {
  const steps: WorkflowRunStep[] = [
    {
      id: "standard-scan",
      layer: "deterministic",
      required: true,
      requested: true,
      status: "running",
      startedAt: input.startedAt,
      completedAt: null,
      executed: false,
      failureReason: null,
      artifacts: {},
    },
  ];
  if (input.request === "full") {
    steps.push(
      {
        id: "cloudflare-source-audit",
        layer: "cloudflare",
        required: true,
        requested: true,
        status: "pending",
        startedAt: null,
        completedAt: null,
        executed: false,
        failureReason: null,
        artifacts: {},
      },
      {
        id: "validate-and-attach",
        layer: "attachment",
        required: true,
        requested: true,
        status: "pending",
        startedAt: null,
        completedAt: null,
        executed: false,
        failureReason: null,
        artifacts: {},
      },
    );
  }
  return {
    schemaVersion: WORKFLOW_RUN_SCHEMA_VERSION,
    revision: 1,
    scanId: input.scanId,
    repositoryPath: input.repositoryPath,
    request: input.request,
    startedAt: input.startedAt,
    completedAt: null,
    steps,
    cloudflare: {
      skillInstalled: null,
      delegationAvailable: null,
      sandboxAvailable: null,
      invoked: false,
      phasesCompleted: [],
      findingsPath: null,
      validation: "not_run",
      attached: false,
      failureReason: null,
    },
    assessmentStatus: "pending",
  };
}

export async function loadWorkflowRun(reportDirectory: string): Promise<WorkflowRunRecord | null> {
  const filePath = path.join(reportDirectory, WORKFLOW_RUN_FILENAME);
  try {
    const contents = await readFile(filePath, "utf8");
    let parsed: unknown;
    try {
      parsed = JSON.parse(contents);
    } catch {
      throw new UsageError("workflow-run.json is not valid JSON");
    }
    const raw = parsed as WorkflowRunRecord;
    assertWorkflowRunShape(raw);
    return raw;
  } catch (error) {
    if (isEnoent(error)) return null;
    throw error;
  }
}

/**
 * Updates workflow-run.json with backup/rename semantics. Writers must retry on revision
 * conflicts; concurrent updates are detected via the monotonic revision field.
 */
export async function updateWorkflowRun(
  reportDirectory: string,
  mutator: (current: WorkflowRunRecord) => WorkflowRunRecord,
): Promise<WorkflowRunRecord> {
  const filePath = path.join(reportDirectory, WORKFLOW_RUN_FILENAME);
  const current = await loadWorkflowRun(reportDirectory);
  if (!current) {
    throw new UsageError("workflow-run.json is missing for this report directory");
  }
  const expectedRevision = current.revision;
  const next = mutator(structuredClone(current));
  next.revision = expectedRevision + 1;
  assertWorkflowRunShape(next);
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  const backupPath = `${filePath}.${process.pid}.bak`;
  try {
    await copyFile(filePath, backupPath);
    await writeWorkflowRunFile(tempPath, next);
    const latest = await loadWorkflowRun(reportDirectory);
    if (!latest || latest.revision !== expectedRevision) {
      await rm(tempPath, { force: true });
      throw new UsageError(
        "workflow-run.json was modified concurrently; reload the report and retry the update",
      );
    }
    await rename(tempPath, filePath);
    await rm(backupPath, { force: true });
    return next;
  } catch (error) {
    await rm(tempPath, { force: true });
    try {
      await copyFile(backupPath, filePath);
    } catch {
      // Keep the last good file if restore fails.
    }
    await rm(backupPath, { force: true });
    throw error;
  }
}

export function recordDeterministicScanCompletion(
  record: WorkflowRunRecord,
  manifest: ScanManifest,
): WorkflowRunRecord {
  const step = record.steps.find((entry) => entry.id === "standard-scan");
  if (!step) throw new UsageError("workflow-run.json is missing the standard-scan step");
  if (step.status === "completed" && step.executed) {
    return record;
  }
  const failed = manifest.toolRuns.some((run) => run.status === "failed");
  step.executed = true;
  step.completedAt = manifest.completedAt;
  step.status = failed ? "failed" : "completed";
  step.failureReason = failed
    ? "One or more required deterministic scanners failed."
    : null;
  step.artifacts = {
    scanManifest: "scan-manifest.json",
    findings: "findings.json",
    report: "report.md",
  };
  record.assessmentStatus = failed
    ? "incomplete"
    : manifest.overallStatus === "complete_with_findings"
      ? "complete_with_findings"
      : manifest.overallStatus === "complete"
        ? "complete"
        : "incomplete";
  if (record.request === "deterministic-only") {
    record.completedAt = manifest.completedAt;
  }
  return record;
}

export function registerCloudflareAgentOutcome(
  record: WorkflowRunRecord,
  input: {
    skillInstalled: boolean;
    delegationAvailable: boolean;
    sandboxAvailable: boolean;
    invoked: boolean;
    phasesCompleted: CloudflareAuditPhase[];
    findingsPath?: string | null;
    status: Extract<WorkflowStepStatus, "completed" | "failed" | "skipped">;
    failureReason?: string | null;
  },
): WorkflowRunRecord {
  if (record.request !== "full") {
    throw new UsageError("Cloudflare registration is only valid for a full workflow request");
  }
  const step = record.steps.find((entry) => entry.id === "cloudflare-source-audit");
  if (!step) throw new UsageError("workflow-run.json is missing the cloudflare-source-audit step");
  const now = new Date().toISOString();
  if (step.status === "completed" && step.executed && input.status !== "failed") {
    throw new UsageError("The cloudflare-source-audit step is already marked completed");
  }
  step.startedAt = step.startedAt ?? now;
  step.completedAt = now;
  step.executed = input.invoked && input.status === "completed";
  step.status = input.status;
  step.failureReason = input.failureReason ?? null;
  const normalizedFindingsPath = input.findingsPath
    ? path.basename(input.findingsPath)
    : null;
  if (normalizedFindingsPath) {
    step.artifacts = { ...step.artifacts, findings: normalizedFindingsPath };
  }
  record.cloudflare = {
    skillInstalled: input.skillInstalled,
    delegationAvailable: input.delegationAvailable,
    sandboxAvailable: input.sandboxAvailable,
    invoked: input.invoked,
    phasesCompleted: CLOUDFLARE_AUDIT_PHASES.filter((phase) =>
      input.phasesCompleted.includes(phase),
    ),
    findingsPath: normalizedFindingsPath,
    validation: record.cloudflare.validation,
    attached: record.cloudflare.attached,
    failureReason: input.failureReason ?? null,
  };
  return record;
}

export function recordSourceAuditValidation(
  record: WorkflowRunRecord,
  input: { passed: boolean; failureReason?: string | null },
): WorkflowRunRecord {
  record.cloudflare.validation = input.passed ? "passed" : "failed";
  if (!input.passed) {
    record.cloudflare.failureReason = input.failureReason ?? "Source audit findings failed validation.";
    record.assessmentStatus = "incomplete";
  }
  return record;
}

export function recordSourceAuditAttachment(
  record: WorkflowRunRecord,
  input: { attached: boolean; failureReason?: string | null },
): WorkflowRunRecord {
  const step = record.steps.find((entry) => entry.id === "validate-and-attach");
  if (!step) {
    if (record.request !== "full") return record;
    throw new UsageError("workflow-run.json is missing the validate-and-attach step");
  }
  const now = new Date().toISOString();
  step.startedAt = step.startedAt ?? now;
  step.completedAt = now;
  step.executed = input.attached;
  step.status = input.attached ? "completed" : "failed";
  step.failureReason = input.failureReason ?? null;
  step.artifacts = {
    ...step.artifacts,
    sourceAuditRecords: "source-audit-records.json",
  };
  record.cloudflare.attached = input.attached;
  if (!input.attached) {
    record.cloudflare.failureReason =
      input.failureReason ?? "Validated findings were not attached to the scan report.";
    record.assessmentStatus = "incomplete";
    record.completedAt = now;
    return record;
  }
  record.completedAt = now;
  return record;
}

export function finalizeWorkflowAssessmentStatus(
  record: WorkflowRunRecord,
  combinedStatus: "complete" | "complete_with_findings" | "incomplete",
): WorkflowRunRecord {
  record.assessmentStatus =
    combinedStatus === "incomplete" ? "incomplete" : combinedStatus;
  if (!record.completedAt && combinedStatus !== "incomplete") {
    record.completedAt = new Date().toISOString();
  }
  return record;
}

async function writeWorkflowRunFile(filePath: string, record: WorkflowRunRecord): Promise<void> {
  await writeFile(filePath, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
}

function assertWorkflowRunShape(value: WorkflowRunRecord): void {
  if (value.schemaVersion !== WORKFLOW_RUN_SCHEMA_VERSION) {
    throw new UsageError(`Unsupported workflow-run schema version: ${String(value.schemaVersion)}`);
  }
  if (!value.scanId || !value.repositoryPath || !Array.isArray(value.steps)) {
    throw new UsageError("workflow-run.json is malformed");
  }
}

import { homedir } from "node:os";
import path from "node:path";
import type { OverallStatus, ToolStatus } from "./types.js";

/**
 * Cursor-skill workflow contract. The CLI does not launch Cloudflare agents.
 * A full audit asks the agent to run the standard scan, then the upstream
 * `security-audit` skill, then `audit validate` and `audit attach`.
 */

export const CLOUDFLARE_AUDIT_PHASES = [
  "reconnaissance",
  "coverage-led-hunting",
  "candidate-validation",
  "structured-findings",
  "independent-verification",
  "reporting",
] as const;

export type CloudflareAuditPhase = (typeof CLOUDFLARE_AUDIT_PHASES)[number];
export type WorkflowRequest = "full" | "deterministic-only";

export interface WorkflowStep {
  id: string;
  layer: "deterministic" | "cloudflare" | "attachment";
  required: boolean;
}

export function planSecurityWorkflow(request: WorkflowRequest): {
  request: WorkflowRequest;
  steps: WorkflowStep[];
} {
  const deterministic: WorkflowStep = {
    id: "standard-scan",
    layer: "deterministic",
    required: true,
  };
  if (request === "deterministic-only") {
    return { request, steps: [deterministic] };
  }
  return {
    request,
    steps: [
      deterministic,
      { id: "cloudflare-source-audit", layer: "cloudflare", required: true },
      { id: "validate-and-attach", layer: "attachment", required: true },
    ],
  };
}

export function cloudflareSkillCandidates(home = homedir()): string[] {
  return [
    path.join(home, ".cursor", "skills", "security-audit", "SKILL.md"),
    path.join(home, ".agents", "skills", "security-audit", "SKILL.md"),
  ];
}

export interface DeterministicScanState {
  status: OverallStatus;
  toolRuns: Array<{ adapter: string; status: ToolStatus }>;
}

export interface CloudflareRunState {
  skillInstalled: boolean;
  delegationAvailable: boolean;
  sandboxAvailable: boolean;
  invoked: boolean;
  phasesCompleted: readonly string[];
  validation: "not_run" | "passed" | "failed";
  attached: boolean;
  failureReason?: string;
}

export interface WorkflowAssessment {
  request: WorkflowRequest;
  deterministicStatus: OverallStatus;
  cloudflareStatus:
    | "not_requested"
    | "not_executed"
    | "incomplete"
    | "validation_failed"
    | "attached";
  cloudflareExecuted: boolean;
  phasesCompleted: CloudflareAuditPhase[];
  combinedStatus: "complete" | "complete_with_findings" | "incomplete";
  comprehensive: false;
  reasons: string[];
  limitations: string[];
}

export function assessSecurityWorkflow(input: {
  request: WorkflowRequest;
  deterministic: DeterministicScanState;
  cloudflare?: CloudflareRunState;
}): WorkflowAssessment {
  const reasons: string[] = [];
  const limitations: string[] = [];
  const deterministicStatus = input.deterministic.status;
  if (input.deterministic.toolRuns.some((run) => run.status === "failed")) {
    reasons.push("A deterministic scanner failed.");
  }
  if (input.request === "deterministic-only") {
    return {
      request: input.request,
      deterministicStatus,
      cloudflareStatus: "not_requested",
      cloudflareExecuted: false,
      phasesCompleted: [],
      combinedStatus: combinedFromDeterministic(deterministicStatus),
      comprehensive: false,
      reasons,
      limitations,
    };
  }

  const cloudflare = input.cloudflare;
  if (!cloudflare?.skillInstalled) {
    reasons.push("The Cloudflare security-audit skill is not installed.");
    return incomplete(input.request, deterministicStatus, "not_executed", reasons, limitations);
  }
  if (!cloudflare.delegationAvailable) {
    reasons.push("This session cannot run the Cloudflare audit's delegated agents.");
    return incomplete(input.request, deterministicStatus, "not_executed", reasons, limitations);
  }
  if (!cloudflare.invoked) {
    reasons.push("The Cloudflare source audit was not started.");
    return incomplete(input.request, deterministicStatus, "not_executed", reasons, limitations);
  }

  const phasesCompleted = CLOUDFLARE_AUDIT_PHASES.filter((phase) =>
    cloudflare.phasesCompleted.includes(phase),
  );
  if (!cloudflare.sandboxAvailable) {
    limitations.push(
      "Target-controlled code was not executed because OS sandbox isolation was not available.",
    );
  }
  if (cloudflare.validation === "failed") {
    reasons.push(cloudflare.failureReason ?? "Cloudflare findings failed validation.");
    return incomplete(
      input.request,
      deterministicStatus,
      "validation_failed",
      reasons,
      limitations,
      phasesCompleted,
    );
  }

  const missing = CLOUDFLARE_AUDIT_PHASES.filter((phase) => !phasesCompleted.includes(phase));
  if (missing.length > 0) {
    reasons.push(`Cloudflare phases did not finish: ${missing.join(", ")}.`);
  }
  if (cloudflare.validation !== "passed" || !cloudflare.attached) {
    reasons.push("Validated findings were not attached to the scan report.");
  }
  if (missing.length > 0 || cloudflare.validation !== "passed" || !cloudflare.attached) {
    return incomplete(
      input.request,
      deterministicStatus,
      "incomplete",
      reasons,
      limitations,
      phasesCompleted,
    );
  }

  return {
    request: input.request,
    deterministicStatus,
    cloudflareStatus: "attached",
    cloudflareExecuted: true,
    phasesCompleted,
    combinedStatus: combinedFromDeterministic(deterministicStatus),
    comprehensive: false,
    reasons,
    limitations,
  };
}

export function renderWorkflowSummary(assessment: WorkflowAssessment): string {
  const phases = assessment.phasesCompleted.length > 0
    ? assessment.phasesCompleted.join(", ")
    : "none recorded";
  return [
    `Deterministic scan: ${assessment.deterministicStatus}.`,
    `Cloudflare source audit: ${assessment.cloudflareStatus}.`,
    `Cloudflare workflow executed: ${assessment.cloudflareExecuted ? "yes" : "no"}.`,
    `Phases completed: ${phases}.`,
    `Combined audit: ${assessment.combinedStatus}.`,
    "Comprehensive coverage: no.",
    ...assessment.reasons.map((reason) => `Reason: ${reason}`),
    ...assessment.limitations.map((limitation) => `Limitation: ${limitation}`),
  ].join("\n");
}

function incomplete(
  request: WorkflowRequest,
  deterministicStatus: OverallStatus,
  cloudflareStatus: WorkflowAssessment["cloudflareStatus"],
  reasons: string[],
  limitations: string[],
  phasesCompleted: CloudflareAuditPhase[] = [],
): WorkflowAssessment {
  return {
    request,
    deterministicStatus,
    cloudflareStatus,
    cloudflareExecuted: false,
    phasesCompleted,
    combinedStatus: "incomplete",
    comprehensive: false,
    reasons,
    limitations,
  };
}

function combinedFromDeterministic(
  status: OverallStatus,
): WorkflowAssessment["combinedStatus"] {
  if (status === "complete" || status === "complete_with_findings") return status;
  return "incomplete";
}

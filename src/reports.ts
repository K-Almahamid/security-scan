import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { validateFindings } from "./findings.js";
import type {
  CanonicalFinding,
  FindingSummary,
  OverallStatus,
  RepositoryProfile,
  ScanManifest,
  ScanPlan,
  Severity,
  ToolRun,
} from "./types.js";
import type { WorkflowRunRecord } from "./workflow-run.js";
import { WORKFLOW_RUN_FILENAME } from "./workflow-run.js";

const severities: Severity[] = ["critical", "high", "medium", "low", "info", "unknown"];

export function determineOverallStatus(toolRuns: ToolRun[], findings: CanonicalFinding[]): OverallStatus {
  if (toolRuns.some((run) => run.status === "failed")) return "incomplete";
  return findings.length > 0 ? "complete_with_findings" : "complete";
}

export function findingCounts(findings: CanonicalFinding[]): Record<Severity, number> {
  return Object.fromEntries(
    severities.map((severity) => [
      severity,
      findings.filter((finding) => finding.severity === severity).length,
    ]),
  ) as Record<Severity, number>;
}

function sumToolFindingCounts(toolRuns: ToolRun[]): number {
  return toolRuns.reduce((total, run) => total + run.findingCount, 0);
}

function sumRecordedParseDiscards(toolRuns: ToolRun[]): number | null {
  if (toolRuns.length === 0) return 0;
  if (toolRuns.some((run) => run.discardedDuringParse === undefined)) return null;
  return toolRuns.reduce((total, run) => total + (run.discardedDuringParse ?? 0), 0);
}

export function buildScanFindingSummary(input: {
  toolRuns: ToolRun[];
  collectedFindings: CanonicalFinding[];
  normalizedFindings: CanonicalFinding[];
}): FindingSummary {
  const perTool = input.toolRuns.map((run) => ({
    id: run.id,
    adapter: run.adapter,
    findingCount: run.findingCount,
    ...(run.discardedDuringParse !== undefined
      ? { discardedDuringParse: run.discardedDuringParse }
      : {}),
  }));
  const accepted = sumToolFindingCounts(input.toolRuns);
  const discardedDuringParse = input.toolRuns.reduce(
    (total, run) => total + (run.discardedDuringParse ?? 0),
    0,
  );
  const preDedupeCollected = input.collectedFindings.length;
  const normalizedUnique = input.normalizedFindings.length;
  const duplicatesRemoved = Math.max(0, preDedupeCollected - normalizedUnique);
  return {
    perTool,
    rawToolFindingsTotal: accepted + (discardedDuringParse ?? 0),
    preDedupeCollected,
    normalizedUnique,
    duplicatesRemoved,
    discardedDuringParse,
  };
}

/** Recompute summary after source-audit attach without losing scan-time dedupe accounting. */
export function buildAttachFindingSummary(input: {
  toolRuns: ToolRun[];
  priorSummary: FindingSummary | undefined;
  deterministicFindings: CanonicalFinding[];
  importableCount: number;
  mergedFindings: CanonicalFinding[];
}): FindingSummary {
  const accepted = sumToolFindingCounts(input.toolRuns);
  const scanPreDedupe = Math.max(
    input.priorSummary?.preDedupeCollected ?? accepted,
    accepted,
  );
  const duplicatesRemovedInScan = Math.max(
    0,
    scanPreDedupe - input.deterministicFindings.length,
  );
  const discardedDuringParse = input.priorSummary
    ? input.priorSummary.discardedDuringParse
    : sumRecordedParseDiscards(input.toolRuns);
  const mergeInput = input.deterministicFindings.length + input.importableCount;
  const duplicatesRemovedInMerge = Math.max(0, mergeInput - input.mergedFindings.length);
  const perTool = input.toolRuns.map((run) => ({
    id: run.id,
    adapter: run.adapter,
    findingCount: run.findingCount,
    ...(run.discardedDuringParse !== undefined
      ? { discardedDuringParse: run.discardedDuringParse }
      : {}),
  }));
  return {
    perTool,
    rawToolFindingsTotal: accepted + (discardedDuringParse ?? 0),
    preDedupeCollected: scanPreDedupe + input.importableCount,
    normalizedUnique: input.mergedFindings.length,
    duplicatesRemoved: duplicatesRemovedInScan + duplicatesRemovedInMerge,
    discardedDuringParse,
  };
}

export function executionSummary(toolRuns: ToolRun[]): ScanManifest["execution"] {
  const failed = toolRuns.filter((run) => run.status === "failed").length;
  const skipped = toolRuns.filter((run) => run.status === "skipped").length;
  const unsupported = toolRuns.filter((run) => run.status === "unsupported").length;
  const completed = toolRuns.filter(
    (run) => run.status === "passed" || run.status === "findings",
  ).length;
  return {
    status: failed > 0 ? "incomplete" : "complete",
    planned: toolRuns.length,
    completed,
    failed,
    skipped,
    unsupported,
  };
}

export function coverageSummary(
  plan: ScanPlan,
  toolRuns: ToolRun[],
): ScanManifest["coverage"] {
  return {
    comprehensive: false,
    plannedStatus:
      toolRuns.length === plan.tools.length &&
      toolRuns.every((run) => run.status === "passed" || run.status === "findings")
        ? "complete"
        : "partial",
    plannedChecks: [
      ...new Set(
        plan.tools.flatMap((tool) =>
          tool.checks.map((check) => `${tool.adapter}:${check}`),
        ),
      ),
    ].sort(),
    supportedChecks: [...plan.supportedChecks].sort(),
    outOfScope: [...plan.outOfScope].sort(),
    unsupported: [...plan.unsupported].sort(),
  };
}

export async function writeReports(input: {
  reportDirectory: string;
  profile: RepositoryProfile;
  plan: ScanPlan;
  manifest: ScanManifest;
  findings: CanonicalFinding[];
  workflowRun?: WorkflowRunRecord;
}): Promise<void> {
  validateFindings(input.findings);
  const staging = `${input.reportDirectory}.partial`;
  await rm(staging, { recursive: true, force: true });
  await mkdir(staging, { recursive: true, mode: 0o700 });
  try {
    const writes = [
      writeJson(path.join(staging, "profile.json"), input.profile),
      writeJson(path.join(staging, "scan-plan.json"), input.plan),
      writeJson(path.join(staging, "scan-manifest.json"), input.manifest),
      writeJson(path.join(staging, "findings.json"), input.findings),
      writeFile(
        path.join(staging, "report.md"),
        renderMarkdownReport(input.manifest, input.findings),
        { mode: 0o600 },
      ),
      writeJson(path.join(staging, "findings.sarif.json"), canonicalFindingsToSarif(input.findings)),
    ];
    if (input.workflowRun) {
      writes.push(
        writeFile(
          path.join(staging, WORKFLOW_RUN_FILENAME),
          `${JSON.stringify(input.workflowRun, null, 2)}\n`,
          { mode: 0o600 },
        ),
      );
    }
    await Promise.all(writes);
    await rename(staging, input.reportDirectory);
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
}

async function writeJson(filePath: string, value: unknown): Promise<void> {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

export function renderMarkdownReport(
  manifest: ScanManifest,
  findings: CanonicalFinding[],
): string {
  const lines = [
    "# Security Scan Report",
    "",
    `- Scan ID: \`${escapeInline(manifest.scanId)}\``,
    `- Status: **${manifest.overallStatus}**`,
    `- Execution completeness: **${manifest.execution.status}** (${manifest.execution.completed}/${manifest.execution.planned} planned tool runs completed)`,
    `- Planned scan coverage: **${manifest.coverage.plannedStatus}**`,
    "- Comprehensive security coverage: **No**",
    `- Repository: \`${escapeInline(manifest.repositoryPath)}\``,
    `- Git: ${gitIdentityLine(manifest)}`,
    `- Started: ${manifest.startedAt}`,
    `- Completed: ${manifest.completedAt}`,
    "",
    "## Executive summary",
    "",
    findings.length === 0
      ? "No normalized findings were reported by completed scanners. This is not a guarantee that the repository is secure."
      : `${findings.length} normalized finding(s) were reported. Prioritize critical and high severity items, then validate potential findings before remediation.`,
    "",
    "## Finding counts",
    "",
    ...findingCountLines(manifest, findings.length),
    "",
    "## Scanner layers",
    "",
    "| Layer | Execution |",
    "|---|---|",
    layerRow(manifest, "trivy", "Trivy"),
    layerRow(manifest, "semgrep", "Semgrep CE"),
    layerRow(manifest, "dart-analyze", "Dart analyzer"),
    layerRow(manifest, "gitleaks", "Gitleaks history"),
    cloudflareRow(manifest),
    "",
    "Trivy, Semgrep, and the Dart analyzer are deterministic CLI adapters. The Cloudflare source audit is a separate agent workflow. This CLI does not launch it. `not executed` means no validated audit was attached.",
    "",
    "## Execution completeness",
    "",
    "| Tool run | Component | Status | Findings | Duration |",
    "|---|---|---:|---:|---:|",
    ...manifest.toolRuns.map(
      (run) =>
        `| ${escapeCell(run.adapter)} | ${escapeCell(run.componentId ?? "repository")} | ${run.status} | ${run.findingCount} | ${run.durationMs} ms |`,
    ),
    "",
    "## Security coverage",
    "",
    "All planned checks completing does not imply comprehensive security coverage.",
    "",
    "**Planned checks**",
    "",
    ...manifest.coverage.plannedChecks.map((check) => `- ${escapeMarkdown(check)}`),
    "",
    "**Supported baseline capabilities**",
    "",
    ...manifest.coverage.supportedChecks.map((check) => `- ${escapeMarkdown(check)}`),
    "",
    "**Explicitly out of scope in standard mode**",
    "",
    ...manifest.coverage.outOfScope.map((entry) => `- ${escapeMarkdown(entry)}`),
    "",
  ];

  if (manifest.coverage.unsupported.length > 0) {
    lines.push(
      "**Unsupported language or tool combinations**",
      "",
      ...manifest.coverage.unsupported.map((gap) => `- ${escapeMarkdown(gap)}`),
      "",
    );
  }

  for (const severity of severities) {
    const group = findings.filter((finding) => finding.severity === severity);
    if (group.length === 0) continue;
    lines.push(`## ${capitalize(severity)} findings`, "");
    for (const finding of group) {
      const location = finding.location.path
        ? `${finding.location.path}${finding.location.startLine ? `:${finding.location.startLine}` : ""}`
        : finding.location.package ?? "No source location";
      lines.push(
        `### ${escapeMarkdown(finding.title)}`,
        "",
        `- ID: \`${finding.id}\``,
        `- Location: \`${escapeInline(location)}\``,
        `- Confidence: ${finding.confidence}`,
        `- Category: ${finding.category}`,
        `- Verification: ${finding.verification}`,
        `- Provenance: ${finding.provenance ?? "deterministic"}`,
        `- Sources: ${finding.sources.map((source) => `\`${escapeInline(`${source.tool}:${source.ruleId}`)}\``).join(", ")}`,
      );
      if (finding.auditVerdict) {
        lines.push(`- Source-audit verdict: ${finding.auditVerdict}`);
      }
      if (finding.dedupe.relatedGroupId) {
        lines.push(
          `- Related root-cause group: \`${finding.dedupe.relatedGroupId}\``,
          `- Relationship: ${escapeMarkdown(finding.dedupe.relatedReason ?? "Related finding")}`,
        );
      }
      if (finding.cve.length > 0) lines.push(`- CVE/advisory: ${finding.cve.join(", ")}`);
      if (finding.cwe.length > 0) lines.push(`- CWE: ${finding.cwe.join(", ")}`);
      if (finding.dependency) {
        lines.push(
          `- Dependency presence: ${finding.dependency.presence}`,
          `- Reachability: ${finding.dependency.reachability.replaceAll("_", " ")}`,
          `- Advisory source: ${escapeMarkdown(finding.dependency.advisorySource)}`,
          `- Advisory observed: ${finding.dependency.advisoryCheckedAt}`,
          "- Publisher verification: not performed by this scan",
        );
      }
      if (finding.description) lines.push("", escapeMarkdown(finding.description));
      if (finding.evidence.redacted) {
        lines.push(
          "",
          `**Evidence (${finding.evidence.kind})**`,
          "",
          "```text",
          safeFence(finding.evidence.redacted),
          "```",
        );
      }
      if (finding.evidence.limitation) {
        lines.push("", `**Evidence limitation:** ${escapeMarkdown(finding.evidence.limitation)}`);
      }
      if (finding.sources.length > 1) {
        lines.push("", "**Consolidated source records**", "");
        for (const source of finding.sources) {
          const sourceLocation = source.location?.path
            ? `${source.location.path}${source.location.startLine ? `:${source.location.startLine}` : ""}`
            : "No source location";
          lines.push(
            `- \`${escapeInline(`${source.tool}:${source.ruleId}`)}\` — ${source.severity ?? "unknown"} / ${source.confidence ?? "unknown"} — \`${escapeInline(sourceLocation)}\` — evidence: ${source.evidence?.kind ?? "unavailable"}`,
          );
        }
      }
      if (finding.remediation) {
        lines.push("", `**Remediation:** ${escapeMarkdown(finding.remediation)}`);
      }
      lines.push("");
    }
  }

  const failedOrSkipped = manifest.toolRuns.filter(
    (run) => run.status === "failed" || run.status === "skipped" || run.status === "unsupported",
  );
  if (failedOrSkipped.length > 0) {
    lines.push(
      "## Incomplete or skipped scans",
      "",
      ...failedOrSkipped.map(
        (run) => `- **${run.id}** — ${run.status}: ${escapeMarkdown(run.reason ?? "No reason supplied")}`,
      ),
      "",
    );
  }

  lines.push(
    "## Cloudflare source audit",
    "",
  );
  if (!manifest.sourceAudit) {
    lines.push(
      "- Status: **not executed**",
      "- Phase completion: none recorded by this CLI scan.",
      "",
      "A full Cursor audit attaches records only after the upstream security-audit skill finishes and `audit validate` succeeds. This section does not mean that workflow ran.",
      "",
    );
  } else {
    lines.push(
      `- Status: **${manifest.sourceAudit.status}**`,
      `- Methodology: ${escapeMarkdown(manifest.sourceAudit.methodology)}`,
      `- Upstream commit: \`${escapeInline(manifest.sourceAudit.upstreamCommit)}\``,
      `- Orchestration: ${manifest.sourceAudit.orchestration}`,
      "- Phase completion: not observed by the CLI. Attachment proves a validated findings file was imported.",
      `- Confirmed: ${manifest.sourceAudit.counts.confirmed}`,
      `- Needs validation: ${manifest.sourceAudit.counts.needs_validation}`,
      `- Rejected: ${manifest.sourceAudit.counts.rejected}`,
      `- Commit binding: ${manifest.sourceAudit.commitBinding ?? "not recorded"}`,
      `- Declared audit commit: ${manifest.sourceAudit.targetCommit ?? "none"}`,
      `- Commit identity: ${manifest.sourceAudit.commitIdentity?.agreement ?? "not recorded"} (agent-attested when present; not proof the hunt ran)`,
      "",
      manifest.sourceAudit.note,
      "",
      "Rejected source-audit candidates are stored in `source-audit-records.json` and are not promoted to confirmed findings.",
      "",
    );
  }

  lines.push(
    "## Handling and limitations",
    "",
    "- Evidence is redacted before normalization; raw artifacts remain outside Git by default.",
    "- Dependency presence is reported separately from reachability; standard mode does not perform reachability analysis.",
    "- Advisory data comes from scanner databases and is not automatically reconciled with publisher advisories.",
    "- Static analysis and dependency scanners do not provide comprehensive security coverage.",
    "- Failed, skipped, and unsupported checks are not treated as passing.",
    "",
  );
  return `${lines.join("\n")}\n`;
}

function findingCountLines(manifest: ScanManifest, normalizedCount: number): string[] {
  const summary = manifest.findingSummary;
  if (!summary) {
    const raw = manifest.toolRuns.reduce((total, run) => total + run.findingCount, 0);
    return [
      `- Per-tool raw findings (sum of tool runs): **${raw}**`,
      `- Normalized unique findings in this report: **${normalizedCount}**`,
      "",
      "Older manifests may omit `findingSummary`; use `toolRuns[].findingCount` and `findings.json` length.",
    ];
  }
  return [
    "- Per-tool raw findings (adapter layer, before global deduplication):",
    "",
    "| Tool run | Adapter | Raw findings |",
    "|---|---|---:|",
    ...summary.perTool.map(
      (entry) =>
        `| ${escapeCell(entry.id)} | ${escapeCell(entry.adapter)} | ${entry.findingCount} |`,
    ),
    "",
    `- **Total raw tool findings:** ${summary.rawToolFindingsTotal}`,
    `- **Collected before deduplication:** ${summary.preDedupeCollected}`,
    `- **Discarded during parse (malformed rows):** ${
      summary.discardedDuringParse === null
        ? "not recorded (legacy manifest; this is not a claim that every raw row was valid)"
        : String(summary.discardedDuringParse)
    }`,
    `- **Duplicates removed:** ${summary.duplicatesRemoved}`,
    `- **Normalized unique findings:** ${summary.normalizedUnique}`,
    "",
    "`manifest.counts` reflects severity buckets for normalized unique findings only.",
  ];
}

const sarifLevel: Record<Severity, "error" | "warning" | "note" | "none"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
  unknown: "none",
};

/** SARIF 2.1.0 export. Canonical JSON remains the source of truth. */
export function canonicalFindingsToSarif(findings: CanonicalFinding[]): {
  version: "2.1.0";
  runs: Array<{
    tool: { driver: { name: string; rules: Array<{ id: string; shortDescription: { text: string } }> } };
    results: Array<{
      ruleId: string;
      level: "error" | "warning" | "note" | "none";
      message: { text: string };
      locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
      partialFingerprints: { primary: string };
    }>;
  }>;
} {
  const rules = new Map<string, { id: string; shortDescription: { text: string } }>();
  const results = findings.map((finding) => {
    const ruleId = finding.evidence.ruleId || finding.sources[0]?.ruleId || finding.id;
    if (!rules.has(ruleId)) rules.set(ruleId, { id: ruleId, shortDescription: { text: finding.title } });
    const uri = finding.location.path ?? "";
    return {
      ruleId,
      level: sarifLevel[finding.severity],
      message: {
        text: finding.evidence.kind === "redacted" ? `${finding.title} Evidence was redacted.` : finding.title,
      },
      locations: [{ physicalLocation: { artifactLocation: { uri } } }],
      partialFingerprints: { primary: finding.fingerprint },
    };
  });
  return {
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "security-scan", rules: [...rules.values()] } },
        results,
      },
    ],
  };
}

function gitIdentityLine(manifest: ScanManifest): string {
  if (!manifest.git) return "not recorded (legacy manifest)";
  if (!manifest.git.commit) return "unavailable";
  const dirty =
    manifest.git.dirty === true
      ? "dirty worktree"
      : manifest.git.dirty === false
        ? "clean worktree"
        : "dirty state unknown";
  return `\`${escapeInline(manifest.git.commit)}\` (${dirty})`;
}

function layerRow(manifest: ScanManifest, adapter: string, label: string): string {
  const runs = manifest.toolRuns.filter((run) => run.adapter === adapter);
  if (runs.length === 0) return `| ${label} | not planned |`;
  const findings = runs.reduce((total, run) => total + run.findingCount, 0);
  const statuses = [...new Set(runs.map((run) => run.status))].join(", ");
  return `| ${label} | ${statuses} (${findings} finding(s)) |`;
}

function cloudflareRow(manifest: ScanManifest): string {
  if (!manifest.sourceAudit) return "| Cloudflare source audit | not executed |";
  const counts = manifest.sourceAudit.counts;
  return `| Cloudflare source audit | ${manifest.sourceAudit.status} (${counts.confirmed} confirmed, ${counts.needs_validation} needs validation, ${counts.rejected} rejected) |`;
}

function escapeMarkdown(value: string): string {
  return value.replace(/[\\`*_{}[\]()#+.!|>-]/g, "\\$&");
}

function escapeCell(value: string): string {
  return escapeMarkdown(value).replace(/\r?\n/g, " ");
}

function escapeInline(value: string): string {
  return value.replace(/`/g, "\\`").replace(/\r?\n/g, " ");
}

function safeFence(value: string): string {
  return value.replace(/```/g, "'''");
}

function capitalize(value: string): string {
  return `${value.charAt(0).toUpperCase()}${value.slice(1)}`;
}

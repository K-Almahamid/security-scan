import { createHash, randomUUID } from "node:crypto";
import {
  createFinding,
  normalizePath,
  normalizeSeverity,
  redactSensitiveText,
} from "../findings.js";
import type { AuditVerdict, CanonicalFinding, Severity } from "../types.js";

export type CloudflareFindingRecord = Record<string, unknown> & {
  verdict: AuditVerdict;
  fingerprint: string;
  title: string;
  description: string;
  trace?: Array<{ file: string; line: number; kind?: string; description?: string }>;
  evidence?: Array<{ file: string; line: number; description: string }>;
};

export interface SourceAuditImportResult {
  validated: boolean;
  importable: CanonicalFinding[];
  rejected: CloudflareFindingRecord[];
  records: CloudflareFindingRecord[];
  counts: Record<AuditVerdict, number>;
}

export function parseCloudflareFindings(raw: unknown): CloudflareFindingRecord[] {
  if (!Array.isArray(raw)) {
    throw new Error("Source audit findings must be a JSON array");
  }
  return raw as CloudflareFindingRecord[];
}

export function importCloudflareFindings(
  repoPath: string,
  records: CloudflareFindingRecord[],
  scannedAt = new Date().toISOString(),
): SourceAuditImportResult {
  const counts: Record<AuditVerdict, number> = {
    confirmed: 0,
    needs_validation: 0,
    rejected: 0,
  };
  const importable: CanonicalFinding[] = [];
  const rejected: CloudflareFindingRecord[] = [];

  for (const record of records) {
    const verdict = record.verdict;
    if (verdict === "rejected") {
      counts.rejected += 1;
      rejected.push(record);
      continue;
    }
    if (verdict !== "confirmed" && verdict !== "needs_validation") {
      throw new Error(`Unsupported source-audit verdict: ${String(verdict)}`);
    }
    counts[verdict] += 1;
    importable.push(mapRecordToCanonical(repoPath, record, scannedAt));
  }

  return {
    validated: true,
    importable,
    rejected,
    records,
    counts,
  };
}

function mapRecordToCanonical(
  repoPath: string,
  record: CloudflareFindingRecord,
  scannedAt: string,
): CanonicalFinding {
  const location = primaryLocation(repoPath, record);
  const severity = record.verdict === "needs_validation"
    ? "unknown"
    : mapCloudflareSeverity(record);
  const confidence =
    record.verdict === "confirmed" && isConfidenceObject(record.confidence)
      ? (record.confidence.score as CanonicalFinding["confidence"])
      : "medium";
  const evidenceText = buildEvidenceText(record);
  const finding = createFinding({
    title: record.title,
    description: record.description,
    severity,
    confidence,
    category: "sast",
    component: null,
    location,
    evidence: {
      text: evidenceText,
      kind: "metadata",
      ...(record.verdict === "needs_validation"
        ? { limitation: "Source-audit candidate; decisive validation not established." }
        : {}),
    },
    source: {
      tool: "cloudflare-source-audit",
      ruleId: `source-audit.${record.verdict}`,
      rawId: record.fingerprint,
    },
    impact:
      record.verdict === "confirmed" && isSeverityObject(record.severity)
        ? redactSensitiveText(record.severity.impact.reason)
        : "",
    remediation:
      record.verdict === "confirmed" && isRemediationObject(record.remediation)
        ? redactSensitiveText(record.remediation.strategy)
        : "",
    scannedAt,
  });

  finding.provenance = "source-audit";
  finding.auditVerdict = record.verdict;
  finding.verification =
    record.verdict === "confirmed" ? "confirmed" : "needs_validation";
  finding.fingerprint = stableHash(`source-audit|${record.fingerprint}`);
  finding.id = randomUUID();
  finding.dedupe.groupId = finding.fingerprint;
  finding.sources[0]!.evidence = finding.evidence;
  return finding;
}

function primaryLocation(
  repoPath: string,
  record: CloudflareFindingRecord,
): CanonicalFinding["location"] {
  const trace = record.trace ?? [];
  const sink = trace.find((entry) => entry.kind === "sink") ?? trace[trace.length - 1];
  const evidence = record.evidence?.[0];
  const file = sink?.file ?? evidence?.file;
  const line = sink?.line ?? evidence?.line;
  if (!file) return {};
  return {
    path: normalizePath(repoPath, file),
    ...(line ? { startLine: line, endLine: line } : {}),
  };
}

function buildEvidenceText(record: CloudflareFindingRecord): string {
  const parts: string[] = [];
  for (const item of record.evidence ?? []) {
    parts.push(
      `${item.file}:${item.line} — ${redactSensitiveText(item.description)}`,
    );
  }
  if (record.verdict === "needs_validation" && Array.isArray(record.blockers)) {
    for (const blocker of record.blockers) {
      parts.push(`blocker: ${redactSensitiveText(String(blocker))}`);
    }
  }
  return parts.join("\n") || redactSensitiveText(record.description);
}

function mapCloudflareSeverity(record: CloudflareFindingRecord): Severity {
  if (!isSeverityObject(record.severity)) return "unknown";
  const overall = record.severity.overall_severity;
  if (overall === "informational") return "info";
  return normalizeSeverity(overall);
}

function isSeverityObject(value: unknown): value is {
  overall_severity: string;
  impact: { reason: string };
} {
  return (
    typeof value === "object" &&
    value !== null &&
    "overall_severity" in value &&
    "impact" in value
  );
}

function isConfidenceObject(value: unknown): value is { score: string } {
  return typeof value === "object" && value !== null && "score" in value;
}

function isRemediationObject(value: unknown): value is { strategy: string } {
  return typeof value === "object" && value !== null && "strategy" in value;
}

function stableHash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function applyProvenanceDefaults(finding: CanonicalFinding): CanonicalFinding {
  if (!finding.provenance) finding.provenance = "deterministic";
  return finding;
}

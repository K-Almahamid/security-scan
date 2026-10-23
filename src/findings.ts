import { createHash, randomUUID } from "node:crypto";
import path from "node:path";
import { z } from "zod";
import type {
  CanonicalFinding,
  DependencyInterpretation,
  FindingEvidence,
  FindingCategory,
  FindingLocation,
  FindingSource,
  Severity,
} from "./types.js";

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

const canonicalFindingSchema = z.object({
  id: z.string().min(1),
  fingerprint: z.string().length(64),
  title: z.string().min(1),
  description: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info", "unknown"]),
  confidence: z.enum(["high", "medium", "low"]),
  category: z.enum(["sast", "sca", "secret", "misconfiguration", "quality"]),
  cwe: z.array(z.string()),
  cve: z.array(z.string()),
  component: z.string().nullable(),
  location: z.object({
    path: z.string().optional(),
    startLine: z.number().int().positive().optional(),
    endLine: z.number().int().positive().optional(),
    endpoint: z.string().optional(),
    package: z.string().optional(),
    installedVersion: z.string().optional(),
  }),
  evidence: z.object({
    redacted: z.string(),
    ruleId: z.string(),
    kind: z.enum(["code", "metadata", "redacted", "unavailable"]),
    limitation: z.string().optional(),
  }),
  sources: z
    .array(
      z.object({
        tool: z.string(),
        ruleId: z.string(),
        rawId: z.string().optional(),
        severity: z.enum(["critical", "high", "medium", "low", "info", "unknown"]).optional(),
        confidence: z.enum(["high", "medium", "low"]).optional(),
        category: z.enum(["sast", "sca", "secret", "misconfiguration", "quality"]).optional(),
        location: z.object({
          path: z.string().optional(),
          startLine: z.number().int().positive().optional(),
          endLine: z.number().int().positive().optional(),
          endpoint: z.string().optional(),
          package: z.string().optional(),
          installedVersion: z.string().optional(),
        }).optional(),
        evidence: z.object({
          redacted: z.string(),
          ruleId: z.string(),
          kind: z.enum(["code", "metadata", "redacted", "unavailable"]),
          limitation: z.string().optional(),
        }).optional(),
      }),
    )
    .min(1),
  dependency: z.object({
    presence: z.literal("confirmed"),
    reachability: z.literal("not_analyzed"),
    advisorySource: z.string(),
    advisoryCheckedAt: z.iso.datetime(),
    publisherVerification: z.literal("not_performed"),
  }).optional(),
  impact: z.string(),
  remediation: z.string(),
  verification: z.enum([
    "confirmed",
    "potential",
    "not_verified",
    "needs_validation",
    "rejected",
  ]),
  provenance: z.enum(["deterministic", "source-audit"]).optional(),
  auditVerdict: z.enum(["confirmed", "needs_validation", "rejected"]).optional(),
  dedupe: z.object({
    groupId: z.string(),
    primary: z.boolean(),
    relatedGroupId: z.string().nullable(),
    relatedReason: z.string().optional(),
  }),
  firstSeen: z.iso.datetime(),
  scannedAt: z.iso.datetime(),
});

const hashedSecretPatterns = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bsk-[A-Za-z0-9_-]{12,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
];

export function normalizeSeverity(value: unknown): Severity {
  const normalized = String(value ?? "").toLowerCase();
  if (normalized === "critical") return "critical";
  if (normalized === "error" || normalized === "high") return "high";
  if (normalized === "warning" || normalized === "medium") return "medium";
  if (normalized === "low") return "low";
  if (normalized === "info" || normalized === "note") return "info";
  return "unknown";
}

export function redactSensitiveText(input: string, maxLength = 2_000): string {
  let output = input;
  for (const pattern of hashedSecretPatterns) {
    output = output.replace(pattern, (match) => `[REDACTED:${shortHash(match)}]`);
  }
  output = output.replace(/\b(Bearer\s+)[A-Za-z0-9._~+/-]+=*/gi, "$1[REDACTED]");
  output = output.replace(
    /((?:"|')?(?:password|secret|token|api[_-]?key)(?:"|')?\s*[:=]\s*(?:"|')?)[^"'\s,;}]+/gi,
    "$1[REDACTED]",
  );
  return output.length > maxLength ? `${output.slice(0, maxLength)}…[TRUNCATED]` : output;
}

export function normalizePath(repoPath: string, candidate: string): string {
  const normalizedCandidate = candidate.replace(/^\/src\/?/, "");
  const absolute = path.isAbsolute(normalizedCandidate)
    ? normalizedCandidate
    : path.resolve(repoPath, normalizedCandidate);
  const relative = path.relative(repoPath, absolute).split(path.sep).join("/");
  if (relative.startsWith("../") || path.isAbsolute(relative)) {
    return normalizedCandidate.split(path.sep).join("/");
  }
  return relative || ".";
}

export function createFinding(input: {
  title: string;
  description?: string;
  severity: Severity;
  category: FindingCategory;
  confidence?: CanonicalFinding["confidence"];
  cwe?: string[];
  cve?: string[];
  component: string | null;
  location: FindingLocation;
  evidence:
    | string
    | {
        text: string;
        kind: FindingEvidence["kind"];
        limitation?: string | undefined;
      };
  source: FindingSource;
  impact?: string;
  remediation?: string;
  dependency?: Omit<DependencyInterpretation, "presence" | "reachability" | "publisherVerification">;
  scannedAt?: string;
}): CanonicalFinding {
  const scannedAt = input.scannedAt ?? new Date().toISOString();
  const evidenceInput =
    typeof input.evidence === "string"
      ? { text: input.evidence, kind: "metadata" as const }
      : input.evidence;
  const redactedEvidence = redactSensitiveText(evidenceInput.text);
  const evidence: FindingEvidence = {
    redacted: redactedEvidence,
    ruleId: input.source.ruleId,
    kind: redactedEvidence.includes("[REDACTED") ? "redacted" : evidenceInput.kind,
    ...(evidenceInput.limitation ? { limitation: evidenceInput.limitation } : {}),
  };
  const confidence = input.confidence ?? "medium";
  const fingerprint = findingFingerprint({
    category: input.category,
    location: input.location,
    cwe: input.cwe ?? [],
    cve: input.cve ?? [],
    ruleId: input.source.ruleId,
  });
  return {
    id: randomUUID(),
    fingerprint,
    title: redactSensitiveText(input.title),
    description: redactSensitiveText(input.description ?? ""),
    severity: input.severity,
    confidence,
    category: input.category,
    cwe: input.cwe ?? [],
    cve: input.cve ?? [],
    component: input.component,
    location: input.location,
    evidence,
    sources: [{
      ...input.source,
      severity: input.severity,
      confidence,
      category: input.category,
      location: structuredClone(input.location),
      evidence: structuredClone(evidence),
    }],
    ...(input.dependency
      ? {
          dependency: {
            presence: "confirmed" as const,
            reachability: "not_analyzed" as const,
            publisherVerification: "not_performed" as const,
            ...input.dependency,
          },
        }
      : {}),
    impact: redactSensitiveText(input.impact ?? ""),
    remediation: redactSensitiveText(input.remediation ?? ""),
    verification: "potential",
    provenance: "deterministic",
    dedupe: {
      groupId: fingerprint,
      primary: true,
      relatedGroupId: null,
    },
    firstSeen: scannedAt,
    scannedAt,
  };
}

export function deduplicateFindings(findings: CanonicalFinding[]): CanonicalFinding[] {
  const groups = new Map<string, CanonicalFinding>();
  for (const finding of findings) {
    const key = duplicateKey(finding);
    const existing = groups.get(key);
    if (!existing) {
      const copy = structuredClone(finding);
      copy.fingerprint = key;
      copy.dedupe.groupId = key;
      groups.set(key, copy);
      continue;
    }
    const sourceKeys = new Set(existing.sources.map((source) => `${source.tool}:${source.ruleId}:${source.rawId ?? ""}`));
    for (const source of finding.sources) {
      const key = `${source.tool}:${source.ruleId}:${source.rawId ?? ""}`;
      if (!sourceKeys.has(key)) existing.sources.push(source);
    }
    if (severityRank[finding.severity] > severityRank[existing.severity]) {
      existing.severity = finding.severity;
    }
    if (!existing.description && finding.description) existing.description = finding.description;
    if (!existing.remediation && finding.remediation) existing.remediation = finding.remediation;
    existing.cwe = [...new Set([...existing.cwe, ...finding.cwe])];
    existing.cve = [...new Set([...existing.cve, ...finding.cve])];
    if (!existing.component && finding.component) existing.component = finding.component;
    if (evidenceRank(finding.evidence) > evidenceRank(existing.evidence)) {
      existing.evidence = structuredClone(finding.evidence);
    }
  }
  const deduplicated = [...groups.values()];
  for (const finding of deduplicated) applyRelatedGroup(finding);
  return deduplicated.sort(
    (left, right) =>
      severityRank[right.severity] - severityRank[left.severity] ||
      (left.location.path ?? "").localeCompare(right.location.path ?? ""),
  );
}

function duplicateKey(finding: CanonicalFinding): string {
  if (
    finding.location.path &&
    (
      finding.sources.some((source) => source.tool === "trivy" && source.ruleId === "DS002") ||
      finding.sources.some((source) =>
        source.tool === "semgrep" && source.ruleId.includes("dockerfile.security.missing-user")
      )
    )
  ) {
    return stableHash(`docker-missing-user|${finding.location.path}`);
  }
  // Advisory identity is authoritative for SCA dedupe. Different CVEs must remain separate.
  return finding.fingerprint;
}

function applyRelatedGroup(finding: CanonicalFinding): void {
  const isHttpSink = finding.sources.some((source) =>
    /insecure-request|cleartext.*http|unencrypted-request/i.test(source.ruleId)
  );
  if (!isHttpSink || !finding.location.path) return;
  finding.dedupe.relatedGroupId = stableHash(`cleartext-http|${finding.location.path}`);
  finding.dedupe.relatedReason =
    "Related cleartext HTTP sinks in the same file; retained separately by location.";
}

function evidenceRank(evidence: FindingEvidence): number {
  return { unavailable: 0, metadata: 1, redacted: 2, code: 3 }[evidence.kind];
}

function findingFingerprint(input: {
  category: FindingCategory;
  location: FindingLocation;
  cwe: string[];
  cve: string[];
  ruleId: string;
}): string {
  let evidenceKey: string;
  if (input.category === "sca") {
    evidenceKey = [
      input.location.package,
      input.location.installedVersion,
      ...input.cve.sort(),
    ].join("|");
  } else if (input.category === "secret") {
    evidenceKey = [
      input.location.path,
      input.location.startLine,
      input.ruleId,
    ].join("|");
  } else {
    evidenceKey = [
      input.location.path,
      input.location.startLine,
      input.location.endLine,
      ...input.cwe.sort(),
      input.ruleId.replace(/^(semgrep|codeql)[.:]/, ""),
    ].join("|");
  }
  return stableHash(`${input.category}|${evidenceKey}`);
}

function stableHash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 10);
}

export function severityAtOrAbove(value: Severity, threshold: Severity): boolean {
  return severityRank[value] >= severityRank[threshold];
}

export function validateFindings(findings: CanonicalFinding[]): void {
  canonicalFindingSchema.array().parse(findings);
}

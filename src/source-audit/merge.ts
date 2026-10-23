import { createHash } from "node:crypto";
import { deduplicateFindings } from "../findings.js";
import type { CanonicalFinding } from "../types.js";
import { applyProvenanceDefaults } from "./import.js";

export function mergeDeterministicWithSourceAudit(
  deterministic: CanonicalFinding[],
  sourceAudit: CanonicalFinding[],
): CanonicalFinding[] {
  const normalized = [
    ...deterministic.map((finding) => applyProvenanceDefaults(structuredClone(finding))),
    ...sourceAudit.map((finding) => applyProvenanceDefaults(structuredClone(finding))),
  ];
  alignCrossProvenanceFindings(normalized);
  return deduplicateFindings(normalized);
}

function alignCrossProvenanceFindings(findings: CanonicalFinding[]): void {
  const buckets = new Map<string, CanonicalFinding[]>();
  for (const finding of findings) {
    const key = locationBucketKey(finding);
    if (!key) continue;
    const bucket = buckets.get(key) ?? [];
    bucket.push(finding);
    buckets.set(key, bucket);
  }

  for (const group of buckets.values()) {
    if (group.length < 2) continue;
    const hasDeterministic = group.some((f) => f.provenance === "deterministic");
    const hasSourceAudit = group.some((f) => f.provenance === "source-audit");
    if (!hasDeterministic || !hasSourceAudit) continue;
    const shared = stableHash(`cross-provenance|${locationBucketKey(group[0]!)}`);
    for (const finding of group) {
      finding.fingerprint = shared;
      finding.dedupe.groupId = shared;
      if (
        finding.provenance === "source-audit" &&
        finding.auditVerdict === "confirmed" &&
        finding.verification === "confirmed"
      ) {
        for (const peer of group) {
          if (peer.provenance === "deterministic" && peer.verification === "potential") {
            peer.verification = "confirmed";
            peer.sources.push(...finding.sources.filter(
              (source) => !peer.sources.some((existing) => existing.tool === source.tool),
            ));
          }
        }
      }
    }
  }
}

function locationBucketKey(finding: CanonicalFinding): string | null {
  if (!finding.location.path || !finding.location.startLine) return null;
  return `${finding.location.path}:${finding.location.startLine}`;
}

function stableHash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

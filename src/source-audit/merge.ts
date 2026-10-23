import { deduplicateFindings } from "../findings.js";
import type { CanonicalFinding } from "../types.js";
import { applyProvenanceDefaults } from "./import.js";

export function mergeDeterministicWithSourceAudit(
  deterministic: CanonicalFinding[],
  sourceAudit: CanonicalFinding[],
): CanonicalFinding[] {
  return deduplicateFindings([
    ...deterministic.map((finding) => applyProvenanceDefaults(structuredClone(finding))),
    ...sourceAudit.map((finding) => applyProvenanceDefaults(structuredClone(finding))),
  ]);
}

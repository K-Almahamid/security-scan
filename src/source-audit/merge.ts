import { deduplicateFindings } from "../findings.js";
import type { CanonicalFinding } from "../types.js";
import { applyProvenanceDefaults } from "./import.js";

/**
 * Merges deterministic findings with importable source-audit findings.
 *
 * Dedup keeps both tools on one fingerprint when they describe the same issue.
 * Provenance defaults are applied so a missing field cannot look like a hunt result.
 */
export function mergeDeterministicWithSourceAudit(
  deterministic: CanonicalFinding[],
  sourceAudit: CanonicalFinding[],
): CanonicalFinding[] {
  return deduplicateFindings([
    ...deterministic.map((finding) => applyProvenanceDefaults(structuredClone(finding))),
    ...sourceAudit.map((finding) => applyProvenanceDefaults(structuredClone(finding))),
  ]);
}

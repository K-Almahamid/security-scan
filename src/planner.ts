import type { SecurityScanConfig } from "./config.js";
import type { RepositoryProfile, ScanPlan } from "./types.js";
import { planScanFromRegistry, selectSemgrepChecks } from "./registry.js";

/** Public planning entry. Tool selection lives in the capability registry. */
export function buildScanPlan(
  profile: RepositoryProfile,
  config: SecurityScanConfig,
): ScanPlan {
  return planScanFromRegistry(profile, config);
}

export { selectSemgrepChecks };

import type { SecurityScanConfig } from "./config.js";
import type { RepositoryProfile, ScanPlan } from "./types.js";
import { planScanFromRegistry, selectSemgrepChecks } from "./registry.js";

export function buildScanPlan(
  profile: RepositoryProfile,
  config: SecurityScanConfig,
): ScanPlan {
  return planScanFromRegistry(profile, config);
}

export { selectSemgrepChecks };

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export function cloudflareValidatorPath(): string {
  return path.join(
    packageRoot,
    "third-party/cloudflare-security-audit/validate-findings.cjs",
  );
}

export function cloudflareSchemaPath(): string {
  return path.join(packageRoot, "third-party/cloudflare-security-audit/report-schema.json");
}

export function readUpstreamCommit(): string {
  try {
    return readFileSync(
      path.join(packageRoot, "third-party/cloudflare-security-audit/UPSTREAM_COMMIT"),
      "utf8",
    ).trim();
  } catch {
    return "unknown";
  }
}

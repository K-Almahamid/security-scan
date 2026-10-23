import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { validateFindings } from "../findings.js";
import { findingCounts, renderMarkdownReport } from "../reports.js";
import type { CanonicalFinding, ScanManifest, SourceAuditAttachment } from "../types.js";
import {
  importCloudflareFindings,
  parseCloudflareFindings,
  type CloudflareFindingRecord,
} from "./import.js";
import { mergeDeterministicWithSourceAudit } from "./merge.js";
import { readUpstreamCommit } from "./paths.js";
import { validateCloudflareFindingsFile } from "./validate.js";

export interface AttachSourceAuditOptions {
  repoPath: string;
  reportDirectory: string;
  sourceAuditFindingsPath: string;
}

export interface AttachSourceAuditResult {
  ok: boolean;
  exitCode: number;
  message: string;
  mergedFindings?: CanonicalFinding[];
}

export async function attachSourceAuditToReport(
  options: AttachSourceAuditOptions,
): Promise<AttachSourceAuditResult> {
  const validation = await validateCloudflareFindingsFile(options.sourceAuditFindingsPath);
  if (!validation.ok) {
    return {
      ok: false,
      exitCode: 3,
      message: `Source audit findings failed Cloudflare schema validation: ${validation.output}`,
    };
  }

  const raw = JSON.parse(
    await readFile(options.sourceAuditFindingsPath, "utf8"),
  ) as unknown;
  const records = parseCloudflareFindings(raw);
  const imported = importCloudflareFindings(options.repoPath, records);

  const findingsPath = path.join(options.reportDirectory, "findings.json");
  const manifestPath = path.join(options.reportDirectory, "scan-manifest.json");
  const deterministic = JSON.parse(await readFile(findingsPath, "utf8")) as CanonicalFinding[];
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ScanManifest;

  const merged = mergeDeterministicWithSourceAudit(deterministic, imported.importable);
  validateFindings(merged);

  const attachment: SourceAuditAttachment = {
    status: "attached",
    methodology: "cloudflare-security-audit-skill",
    upstreamCommit: readUpstreamCommit(),
    sourceFindingsPath: path.basename(options.sourceAuditFindingsPath),
    validatedAt: new Date().toISOString(),
    orchestration: "cursor-agent",
    counts: imported.counts,
    note:
      "Source-level audit is agentic and separate from deterministic scanner execution. " +
      "Rejected candidates are preserved in source-audit-records.json.",
  };

  manifest.sourceAudit = attachment;
  manifest.counts = findingCounts(merged);
  if (merged.length > 0 && manifest.overallStatus === "complete") {
    manifest.overallStatus = "complete_with_findings";
  }

  await writeFile(
    path.join(options.reportDirectory, "source-audit-records.json"),
    `${JSON.stringify(records as CloudflareFindingRecord[], null, 2)}\n`,
    { mode: 0o600 },
  );
  await writeFile(findingsPath, `${JSON.stringify(merged, null, 2)}\n`, { mode: 0o600 });
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  await writeFile(
    path.join(options.reportDirectory, "report.md"),
    renderMarkdownReport(manifest, merged),
    { mode: 0o600 },
  );

  return {
    ok: true,
    exitCode: 0,
    message: "Attached validated source-audit findings to the scan report.",
    mergedFindings: merged,
  };
}

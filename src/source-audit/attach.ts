import { copyFile, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { UsageError, isEnoent } from "../errors.js";
import { validateFindings } from "../findings.js";
import { assertPathInsideRepository } from "../profile.js";
import { findingCounts, renderMarkdownReport } from "../reports.js";
import type { CanonicalFinding, ScanManifest, SourceAuditAttachment } from "../types.js";
import { importCloudflareFindings, parseCloudflareFindings } from "./import.js";
import { mergeDeterministicWithSourceAudit } from "./merge.js";
import { readUpstreamCommit } from "./paths.js";
import { validateCloudflareFindingsFile } from "./validate.js";
import {
  loadWorkflowRun,
  recordSourceAuditAttachment,
  recordSourceAuditValidation,
  updateWorkflowRun,
} from "../workflow-run.js";

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
  try {
    return await attachInsideRepository(options);
  } catch (error) {
    if (error instanceof UsageError) {
      return { ok: false, exitCode: error.exitCode, message: error.message };
    }
    return {
      ok: false,
      exitCode: 4,
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

async function attachInsideRepository(
  options: AttachSourceAuditOptions,
): Promise<AttachSourceAuditResult> {
  const reportDirectory = await assertPathInsideRepository(
    options.repoPath,
    options.reportDirectory,
  );
  const validation = await validateCloudflareFindingsFile(options.sourceAuditFindingsPath);
  if (!validation.ok) {
    await updateWorkflowRunOnValidationFailure(
      reportDirectory,
      validation.output || "Source audit findings failed validation.",
    );
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
  for (const finding of imported.importable) {
    if (!finding.location.path) continue;
    await assertPathInsideRepository(options.repoPath, finding.location.path);
  }

  const findingsPath = path.join(reportDirectory, "findings.json");
  const manifestPath = path.join(reportDirectory, "scan-manifest.json");
  const deterministic = JSON.parse(await readFile(findingsPath, "utf8")) as CanonicalFinding[];
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ScanManifest;
  const repoPath = await assertPathInsideRepository(options.repoPath, ".");
  if (manifest.repositoryPath !== repoPath) {
    throw new UsageError("Report repositoryPath does not match --repo");
  }

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
      "Rejected candidates are preserved in source-audit-records.json. " +
      "Attachment does not execute repository code.",
  };

  manifest.sourceAudit = attachment;
  manifest.counts = findingCounts(merged);
  if (merged.length > 0 && manifest.overallStatus === "complete") {
    manifest.overallStatus = "complete_with_findings";
  }

  await updateWorkflowRunAfterAttach(reportDirectory, options.sourceAuditFindingsPath);

  await commitReportFiles([
    {
      filePath: path.join(reportDirectory, "source-audit-records.json"),
      contents: `${JSON.stringify(records, null, 2)}\n`,
    },
    { filePath: findingsPath, contents: `${JSON.stringify(merged, null, 2)}\n` },
    { filePath: manifestPath, contents: `${JSON.stringify(manifest, null, 2)}\n` },
    {
      filePath: path.join(reportDirectory, "report.md"),
      contents: renderMarkdownReport(manifest, merged),
    },
  ]);

  return {
    ok: true,
    exitCode: 0,
    message: "Attached validated source-audit findings to the scan report.",
    mergedFindings: merged,
  };
}

async function updateWorkflowRunOnValidationFailure(
  reportDirectory: string,
  failureReason: string,
): Promise<void> {
  const existing = await loadWorkflowRun(reportDirectory);
  if (!existing) return;
  await updateWorkflowRun(reportDirectory, (current) => {
    let next = recordSourceAuditValidation(current, { passed: false, failureReason });
    next = recordSourceAuditAttachment(next, {
      attached: false,
      failureReason,
    });
    return next;
  });
}

async function updateWorkflowRunAfterAttach(
  reportDirectory: string,
  sourceAuditFindingsPath: string,
): Promise<void> {
  const existing = await loadWorkflowRun(reportDirectory);
  if (!existing) return;
  await updateWorkflowRun(reportDirectory, (current) => {
    let next = recordSourceAuditValidation(current, { passed: true });
    next = recordSourceAuditAttachment(next, { attached: true });
    // Report-attachment state: record that validated findings were imported.
    // This does not set cloudflare.invoked or phases; full-workflow steps exist
    // only when workflow-run.request is "full".
    next.cloudflare.findingsPath = path.basename(sourceAuditFindingsPath);
    next.cloudflare.validation = "passed";
    next.cloudflare.attached = true;
    return next;
  });
}

export async function commitReportFiles(
  files: { filePath: string; contents: string }[],
  renameFile: (from: string, to: string) => Promise<void> = rename,
): Promise<void> {
  const backups: { filePath: string; backupPath: string }[] = [];
  const temps: string[] = [];
  const created: string[] = [];
  try {
    for (const file of files) {
      const backupPath = `${file.filePath}.${process.pid}.bak`;
      const tempPath = `${file.filePath}.${process.pid}.tmp`;
      try {
        await copyFile(file.filePath, backupPath);
        backups.push({ filePath: file.filePath, backupPath });
      } catch (error) {
        if (!isEnoent(error)) throw error;
        created.push(file.filePath);
      }
      await writeFile(tempPath, file.contents, { mode: 0o600 });
      temps.push(tempPath);
    }
    for (let index = 0; index < files.length; index += 1) {
      const file = files[index];
      const tempPath = temps[index];
      if (!file || !tempPath) throw new Error("Report commit lost a staged file");
      await renameFile(tempPath, file.filePath);
    }
    await Promise.all(backups.map((backup) => rm(backup.backupPath, { force: true })));
  } catch (error) {
    await Promise.all(temps.map((temp) => rm(temp, { force: true })));
    for (const filePath of created.reverse()) await rm(filePath, { force: true });
    for (const backup of [...backups].reverse()) {
      await copyFile(backup.backupPath, backup.filePath);
    }
    await Promise.all(backups.map((backup) => rm(backup.backupPath, { force: true })));
    throw error;
  }
}

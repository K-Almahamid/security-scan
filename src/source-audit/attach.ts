import { copyFile, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { UsageError, isEnoent } from "../errors.js";
import { validateFindings } from "../findings.js";
import { assertPathInsideRepository } from "../profile.js";
import { buildAttachFindingSummary, canonicalFindingsToSarif, findingCounts, renderMarkdownReport } from "../reports.js";
import { readRepositoryGit } from "../scanner.js";
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
  /** Full Git commit the audit claims to have reviewed. Omit to leave the attachment unbound. */
  targetCommit?: string;
}

export type AuditCommitBinding = NonNullable<SourceAuditAttachment["commitBinding"]>;
export type AuditCommitIdentity = NonNullable<SourceAuditAttachment["commitIdentity"]>;

export interface AttestedAuditIdentity {
  commit: string | null;
  dirty: boolean | null;
  repositoryPath: string | null;
}

const AUDIT_IDENTITY_KEYS = new Set(["version", "repositoryPath", "commit", "dirty"]);

export function auditIdentitySidecarPath(findingsPath: string): string {
  const parsed = path.parse(findingsPath);
  if (parsed.ext.toLowerCase() !== ".json") return `${findingsPath}.identity.json`;
  return path.join(parsed.dir, `${parsed.name}.identity.json`);
}

export function parseAttestedAuditIdentity(raw: unknown): AttestedAuditIdentity {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new UsageError("Audit identity sidecar must be a JSON object.");
  }
  const record = raw as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!AUDIT_IDENTITY_KEYS.has(key)) {
      throw new UsageError(`Unknown audit identity field: ${key}`);
    }
  }
  if (record.version !== 1) throw new UsageError("Audit identity version must be 1.");
  let repositoryPath: string | null = null;
  if (record.repositoryPath !== undefined && record.repositoryPath !== null) {
    if (typeof record.repositoryPath !== "string" || !record.repositoryPath.trim()) {
      throw new UsageError("Audit identity repositoryPath must be a non-empty path.");
    }
    repositoryPath = record.repositoryPath;
  }
  let commit: string | null = null;
  if (record.commit !== undefined && record.commit !== null) {
    if (typeof record.commit !== "string" || !/^[0-9a-f]{40}$/i.test(record.commit.trim())) {
      throw new UsageError("Audit identity commit must be a full 40-character Git commit.");
    }
    commit = record.commit.trim().toLowerCase();
  }
  let dirty: boolean | null = null;
  if (record.dirty !== undefined && record.dirty !== null) {
    if (typeof record.dirty !== "boolean") throw new UsageError("Audit identity dirty must be a boolean.");
    dirty = record.dirty;
  }
  return { commit, dirty, repositoryPath };
}

export async function loadAttestedAuditIdentity(
  findingsPath: string,
): Promise<AttestedAuditIdentity | null> {
  const sidecar = auditIdentitySidecarPath(findingsPath);
  let text: string;
  try {
    text = await readFile(sidecar, "utf8");
  } catch (error) {
    if (isEnoent(error)) return null;
    throw error;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new UsageError(`Audit identity sidecar is not valid JSON: ${path.basename(sidecar)}`);
  }
  return parseAttestedAuditIdentity(parsed);
}

/**
 * Compares agent-attested identity with the commit the CLI recorded at scan time.
 *
 * `--target-commit` and a sidecar commit must agree. A known dirty-state
 * disagreement is rejected. HEAD moving after the scan is recorded as
 * `observed` and is not, by itself, a contradiction.
 * `matched` means the attestation equals a clean recorded commit. It is not
 * proof that a hunt process ran.
 *
 * @returns A binding, or a message suitable for exit code 3. Does not write files.
 */
export function resolveAuditCommitBinding(input: {
  git: ScanManifest["git"];
  targetCommit?: string | undefined;
  attested?: AttestedAuditIdentity | null;
  observed?: { commit: string | null; dirty: boolean | null } | null;
  repositoryPath?: string;
}):
  | { ok: true; binding: AuditCommitBinding; targetCommit: string | null; identity: AuditCommitIdentity }
  | { ok: false; message: string } {
  const flag = normalizeDeclaredCommit(input.targetCommit);
  if (flag === "invalid") {
    return { ok: false, message: "--target-commit must be the full 40-character Git commit." };
  }
  const attestedCommit = input.attested?.commit ?? null;
  if (flag && attestedCommit && flag !== attestedCommit) {
    return {
      ok: false,
      message: `Audit identity commit ${attestedCommit} does not match --target-commit ${flag}.`,
    };
  }
  if (input.attested?.repositoryPath && input.repositoryPath) {
    const attestedPath = path.resolve(input.attested.repositoryPath);
    const repoPath = path.resolve(input.repositoryPath);
    if (attestedPath !== repoPath) {
      return {
        ok: false,
        message: `Audit identity repository ${attestedPath} does not match --repo ${repoPath}.`,
      };
    }
  }
  if (
    input.attested?.dirty != null &&
    input.git?.dirty != null &&
    input.attested.dirty !== input.git.dirty
  ) {
    return {
      ok: false,
      message: "Audit identity dirty state contradicts the dirty state recorded for this scan.",
    };
  }
  const declared = flag ?? attestedCommit ?? "";
  if (!declared) {
    const binding: AuditCommitBinding = input.git ? "unbound" : "legacy-scan";
    return { ok: true, binding, targetCommit: null, identity: commitIdentity(input, binding, null) };
  }
  if (!input.git?.commit) {
    return {
      ok: false,
      message:
        "This scan did not record a Git commit. Refusing to attach an audit that names a commit, because compatibility cannot be checked.",
    };
  }
  if (input.git.commit.toLowerCase() !== declared) {
    return {
      ok: false,
      message: `Audit commit ${declared} does not match the scanned commit ${input.git.commit}.`,
    };
  }
  if (input.git.dirty !== false || input.attested?.dirty === true) {
    return {
      ok: false,
      message:
        input.git.dirty === true || input.attested?.dirty === true
          ? `Scan commit ${input.git.commit} had a dirty worktree, so that commit does not identify the scanned tree.`
          : `Dirty state for scan commit ${input.git.commit} was not recorded. Refusing to treat the audit commit as a match.`,
    };
  }
  return {
    ok: true,
    binding: "matched",
    targetCommit: declared,
    identity: commitIdentity(input, "matched", declared),
  };
}

function normalizeDeclaredCommit(value: string | undefined): string | null | "invalid" {
  const trimmed = value?.trim().toLowerCase() ?? "";
  if (!trimmed) return null;
  return /^[0-9a-f]{40}$/.test(trimmed) ? trimmed : "invalid";
}

function commitIdentity(
  input: {
    git: ScanManifest["git"];
    attested?: AttestedAuditIdentity | null;
    observed?: { commit: string | null; dirty: boolean | null } | null;
  },
  binding: AuditCommitBinding,
  declared: string | null,
): AuditCommitIdentity {
  const attested = input.attested || declared
    ? {
        commit: declared,
        dirty: input.attested?.dirty ?? null,
        repositoryPath: input.attested?.repositoryPath ?? null,
      }
    : null;
  return {
    attested,
    scan: input.git ? { commit: input.git.commit, dirty: input.git.dirty } : null,
    observed: input.observed ?? null,
    agreement:
      binding === "matched"
        ? "attested-matches-scan"
        : binding === "legacy-scan"
          ? "legacy-unverified"
          : "not-checked",
  };
}

export interface AttachSourceAuditResult {
  ok: boolean;
  exitCode: number;
  message: string;
  mergedFindings?: CanonicalFinding[];
}

/**
 * Validates a Cloudflare findings file and merges importable records into a scan report.
 *
 * Writes are atomic per file with backups. A binding or schema failure returns
 * exit code 3 and leaves the report unchanged. Repeating the same attach does
 * not multiply sources.
 */
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
  const attested = await loadAttestedAuditIdentity(options.sourceAuditFindingsPath);
  if (attested?.repositoryPath) {
    const attestedPath = path.isAbsolute(attested.repositoryPath)
      ? path.resolve(attested.repositoryPath)
      : path.resolve(repoPath, attested.repositoryPath);
    let same = path.resolve(attestedPath) === path.resolve(repoPath);
    try {
      same = (await realpath(attestedPath)) === (await realpath(repoPath));
    } catch {
      same = path.resolve(attestedPath) === path.resolve(repoPath);
    }
    if (!same) {
      throw new UsageError(
        `Audit identity repository ${attestedPath} does not match --repo ${repoPath}.`,
      );
    }
    attested.repositoryPath = repoPath;
  }
  const observed = await readRepositoryGit(repoPath);
  const binding = resolveAuditCommitBinding({
    git: manifest.git,
    repositoryPath: repoPath,
    attested,
    observed,
    ...(options.targetCommit ? { targetCommit: options.targetCommit } : {}),
  });
  if (!binding.ok) throw new UsageError(binding.message);

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
      "Attachment does not execute repository code. " +
      commitBindingNote(binding.binding, binding.identity),
    commitBinding: binding.binding,
    targetCommit: binding.targetCommit,
    commitIdentity: binding.identity,
  };

  manifest.sourceAudit = attachment;
  manifest.counts = findingCounts(merged);
  manifest.findingSummary = buildAttachFindingSummary({
    toolRuns: manifest.toolRuns,
    priorSummary: manifest.findingSummary,
    deterministicFindings: deterministic,
    importableCount: imported.importable.length,
    mergedFindings: merged,
  });
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
    {
      filePath: path.join(reportDirectory, "findings.sarif.json"),
      contents: `${JSON.stringify(canonicalFindingsToSarif(merged), null, 2)}\n`,
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

function commitBindingNote(binding: AuditCommitBinding, identity: AuditCommitIdentity): string {
  const divergence =
    identity.observed?.commit &&
    identity.scan?.commit &&
    identity.observed.commit !== identity.scan.commit
      ? " HEAD at attach time differs from the scanned commit. That later movement is recorded and is not the audit identity."
      : "";
  if (binding === "matched") {
    return (
      "Agent-attested commit matches the clean Git commit the CLI recorded for this scan. " +
      "The CLI did not run the hunt, so this is not proof the audit executed." +
      divergence
    );
  }
  if (binding === "legacy-scan") {
    return "This scan manifest has no Git identity. Attachment does not claim a verified commit match." + divergence;
  }
  return "The audit did not attest a commit. Attachment does not claim the hunt reviewed this scan's revision." + divergence;
}

/**
 * Replaces report files only after every temp file is written.
 *
 * Existing files are copied aside first. A failure restores those backups and
 * deletes files that did not exist before the attempt.
 */
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

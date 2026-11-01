import assert from "node:assert/strict";
import { cp, mkdtemp, mkdir, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { createFinding, validateFindings } from "../src/findings.js";
import {
  attachSourceAuditToReport,
  auditIdentitySidecarPath,
  commitReportFiles,
  parseAttestedAuditIdentity,
  resolveAuditCommitBinding,
} from "../src/source-audit/attach.js";
import {
  importCloudflareFindings,
  parseCloudflareFindings,
} from "../src/source-audit/import.js";
import { mergeDeterministicWithSourceAudit } from "../src/source-audit/merge.js";
import { validateCloudflareFindingsFile } from "../src/source-audit/validate.js";
import type { ScanManifest } from "../src/types.js";

const fixtureDir = path.dirname(fileURLToPath(import.meta.url));
const samplePath = path.join(fixtureDir, "fixtures/cloudflare-findings-sample.json");

describe("Cloudflare source-audit integration", () => {
  it("validates producer-shaped findings with the vendored validator", async () => {
    const result = await validateCloudflareFindingsFile(samplePath);
    assert.equal(result.ok, true);
  });

  it("imports confirmed and needs_validation without promoting rejected records", async () => {
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-repo-"));
    const raw = JSON.parse(await readFile(samplePath, "utf8")) as unknown;
    const imported = importCloudflareFindings(repo, parseCloudflareFindings(raw));
    assert.equal(imported.importable.length, 2);
    assert.equal(imported.rejected.length, 1);
    assert.equal(imported.counts.rejected, 1);
    const confirmed = imported.importable.find((f) => f.auditVerdict === "confirmed");
    const blocked = imported.importable.find((f) => f.auditVerdict === "needs_validation");
    assert.ok(confirmed);
    assert.equal(confirmed.verification, "confirmed");
    assert.equal(confirmed.severity, "medium");
    assert.ok(blocked);
    assert.equal(blocked.verification, "needs_validation");
    assert.equal(blocked.severity, "unknown");
    validateFindings(imported.importable);
  });

  it("keeps same-title findings from different sources separate", () => {
    const deterministic = createFinding({
      title: "Missing ownership check",
      severity: "high",
      category: "sast",
      component: null,
      location: { path: "src/handler.c", startLine: 30, endLine: 30 },
      evidence: "static rule hit",
      source: { tool: "semgrep", ruleId: "semgrep.c.ownership" },
      scannedAt: "2026-01-01T00:00:00.000Z",
    });
    const sourceAudit = createFinding({
      title: "Missing ownership check",
      severity: "medium",
      category: "sast",
      component: null,
      location: { path: "src/handler.c", startLine: 30, endLine: 30 },
      evidence: "reproduced in sandbox",
      source: { tool: "cloudflare-source-audit", ruleId: "source-audit.confirmed" },
      scannedAt: "2026-01-01T00:00:00.000Z",
    });
    sourceAudit.provenance = "source-audit";
    sourceAudit.auditVerdict = "confirmed";
    sourceAudit.verification = "confirmed";

    const merged = mergeDeterministicWithSourceAudit([deterministic], [sourceAudit]);
    assert.equal(merged.length, 2);
    const semgrep = merged.find((finding) => finding.provenance === "deterministic");
    const audit = merged.find((finding) => finding.provenance === "source-audit");
    assert.equal(semgrep?.verification, "potential");
    assert.equal(audit?.verification, "confirmed");
    assert.equal(audit?.auditVerdict, "confirmed");
  });

  it("keeps distinct CVEs at the same dependency path separate", () => {
    const first = createFinding({
      title: "CVE-1111",
      severity: "high",
      category: "sca",
      component: null,
      location: { package: "lodash", installedVersion: "4.17.20" },
      evidence: "advisory",
      cve: ["CVE-1111"],
      source: { tool: "trivy", ruleId: "CVE-1111" },
    });
    const second = createFinding({
      title: "CVE-2222",
      severity: "medium",
      category: "sca",
      component: null,
      location: { package: "lodash", installedVersion: "4.17.20" },
      evidence: "advisory",
      cve: ["CVE-2222"],
      source: { tool: "trivy", ruleId: "CVE-2222" },
    });
    assert.equal(mergeDeterministicWithSourceAudit([first], [second]).length, 2);
  });

  it("does not treat invalid source-audit files as attachable", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "security-scan-invalid-"));
    const invalidPath = path.join(dir, "findings.json");
    await writeFile(invalidPath, "[{\"verdict\":\"confirmed\"}]\n");
    const result = await validateCloudflareFindingsFile(invalidPath);
    assert.equal(result.ok, false);
  });

  it("attach fails closed when validation fails and does not mutate reports", async () => {
    const reportDir = await mkdtemp(path.join(os.tmpdir(), "security-scan-report-"));
    const manifest: ScanManifest = {
      schemaVersion: 2,
      scanId: "test",
      repositoryPath: "/tmp/repo",
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:00.000Z",
      overallStatus: "complete",
      mode: "standard",
      toolRuns: [],
      execution: {
        status: "complete",
        planned: 0,
        completed: 0,
        failed: 0,
        skipped: 0,
        unsupported: 0,
      },
      coverage: {
        comprehensive: false,
        plannedStatus: "complete",
        plannedChecks: [],
        supportedChecks: [],
        outOfScope: [],
        unsupported: [],
      },
      coverageGaps: [],
      counts: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        unknown: 0,
      },
      rawArtifactsPath: "/tmp/raw",
      reportDirectory: reportDir,
    };
    await writeFile(path.join(reportDir, "findings.json"), "[]\n");
    await writeFile(path.join(reportDir, "scan-manifest.json"), `${JSON.stringify(manifest)}\n`);
    const invalidPath = path.join(reportDir, "bad-findings.json");
    await writeFile(invalidPath, "[{\"verdict\":\"confirmed\"}]\n");
    const result = await attachSourceAuditToReport({
      repoPath: reportDir,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: invalidPath,
    });
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 3);
    const findings = JSON.parse(await readFile(path.join(reportDir, "findings.json"), "utf8"));
    assert.deepEqual(findings, []);
  });

  it("does not merge unrelated findings that only share a line", () => {
    const deterministic = createFinding({
      title: "SQL injection",
      severity: "high",
      category: "sast",
      component: null,
      location: { path: "src/handler.c", startLine: 30, endLine: 30 },
      evidence: "query",
      source: { tool: "semgrep", ruleId: "sql-injection" },
      scannedAt: "2026-01-01T00:00:00.000Z",
    });
    const sourceAudit = createFinding({
      title: "Missing ownership check",
      severity: "medium",
      category: "sast",
      component: null,
      location: { path: "src/handler.c", startLine: 30, endLine: 30 },
      evidence: "ownership",
      source: { tool: "cloudflare-source-audit", ruleId: "source-audit.confirmed" },
      scannedAt: "2026-01-01T00:00:00.000Z",
    });
    sourceAudit.provenance = "source-audit";
    sourceAudit.auditVerdict = "confirmed";
    sourceAudit.verification = "confirmed";
    const merged = mergeDeterministicWithSourceAudit([deterministic], [sourceAudit]);
    assert.equal(merged.length, 2);
    assert.equal(merged.find((finding) => finding.title === "SQL injection")?.verification, "potential");
  });

  it("rejects a source-audit path that escapes the repository", () => {
    assert.throws(
      () =>
        importCloudflareFindings("/tmp/repo", [
          {
            verdict: "confirmed",
            fingerprint: "escape",
            title: "Escape",
            description: "Path leaves the repository.",
            trace: [{ file: "../../etc/passwd", line: 1, kind: "sink" }],
          },
        ]),
      /escapes the repository/,
    );
  });

  it("restores report files when a commit fails midway", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "security-scan-commit-"));
    const findingsPath = path.join(dir, "findings.json");
    const manifestPath = path.join(dir, "scan-manifest.json");
    await writeFile(findingsPath, "[]\n");
    await writeFile(manifestPath, "{}\n");
    let renamed = 0;
    await assert.rejects(
      () =>
        commitReportFiles(
          [
            { filePath: findingsPath, contents: "[1]\n" },
            { filePath: manifestPath, contents: "{\"ok\":true}\n" },
          ],
          async (from, to) => {
            renamed += 1;
            if (renamed === 2) throw new Error("injected commit failure");
            const { rename } = await import("node:fs/promises");
            await rename(from, to);
          },
        ),
      /injected commit failure/,
    );
    assert.equal(await readFile(findingsPath, "utf8"), "[]\n");
    assert.equal(await readFile(manifestPath, "utf8"), "{}\n");
    const leftovers = (await readdir(dir)).filter((name) => name.includes(".bak") || name.includes(".tmp"));
    assert.deepEqual(leftovers, []);
  });

  it("attaches the committed scan fixture without dropping rejected records", async () => {
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-attach-"));
    const reportDir = await copyMinimalScan(repo);
    const profileBefore = await readFile(path.join(reportDir, "profile.json"), "utf8");
    const planBefore = await readFile(path.join(reportDir, "scan-plan.json"), "utf8");
    const first = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: samplePath,
    });
    assert.equal(first.ok, true, first.message);
    assert.equal(first.exitCode, 0);
    const findings = JSON.parse(await readFile(path.join(reportDir, "findings.json"), "utf8")) as {
      auditVerdict?: string;
      verification: string;
      severity: string;
      provenance?: string;
    }[];
    assert.equal(findings.length, 2);
    assert.equal(findings.filter((finding) => finding.auditVerdict === "rejected").length, 0);
    assert.equal(findings.find((finding) => finding.auditVerdict === "needs_validation")?.verification, "needs_validation");
    assert.equal(findings.find((finding) => finding.auditVerdict === "needs_validation")?.severity, "unknown");
    assert.ok(findings.every((finding) => finding.provenance === "source-audit"));
    const records = JSON.parse(await readFile(path.join(reportDir, "source-audit-records.json"), "utf8")) as {
      verdict: string;
    }[];
    assert.equal(records.filter((record) => record.verdict === "rejected").length, 1);
    const manifest = JSON.parse(await readFile(path.join(reportDir, "scan-manifest.json"), "utf8")) as {
      coverage: { comprehensive: boolean; unsupported: string[] };
      coverageGaps: string[];
      sourceAudit: { counts: { confirmed: number; needs_validation: number; rejected: number } };
      counts: { medium: number; unknown: number };
      overallStatus: string;
    };
    assert.equal(manifest.coverage.comprehensive, false);
    assert.deepEqual(manifest.coverageGaps, []);
    assert.equal(manifest.sourceAudit.counts.confirmed, 1);
    assert.equal(manifest.sourceAudit.counts.needs_validation, 1);
    assert.equal(manifest.sourceAudit.counts.rejected, 1);
    assert.equal(manifest.counts.medium, 1);
    assert.equal(manifest.counts.unknown, 1);
    assert.equal(manifest.overallStatus, "complete_with_findings");
    assert.equal(await readFile(path.join(reportDir, "profile.json"), "utf8"), profileBefore);
    assert.equal(await readFile(path.join(reportDir, "scan-plan.json"), "utf8"), planBefore);
    const report = await readFile(path.join(reportDir, "report.md"), "utf8");
    assert.match(report, /Comprehensive security coverage: \*\*No\*\*/);
    assert.match(report, /Rejected source-audit candidates/);

    const second = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: samplePath,
    });
    assert.equal(second.ok, true, second.message);
    const repeated = JSON.parse(await readFile(path.join(reportDir, "findings.json"), "utf8")) as {
      fingerprint: string;
      sources: unknown[];
    }[];
    assert.equal(repeated.length, findings.length);
    assert.deepEqual(
      repeated.map((finding) => finding.sources.length),
      findings.map(() => 1),
    );
  });

  it("does not attach duplicate, malformed, or escaping audit input", async () => {
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-attach-reject-"));
    const reportDir = await copyMinimalScan(repo);
    const raw = JSON.parse(await readFile(samplePath, "utf8")) as unknown[];
    const duplicatePath = path.join(repo, "duplicate.json");
    await writeFile(duplicatePath, JSON.stringify([...raw, raw[0]]));
    const duplicate = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: duplicatePath,
    });
    assert.equal(duplicate.ok, false);
    assert.equal(duplicate.exitCode, 3);

    const malformedPath = path.join(repo, "malformed.json");
    await writeFile(malformedPath, "{\"schemaVersion\":99}\n");
    const malformed = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: malformedPath,
    });
    assert.equal(malformed.ok, false);
    assert.equal(malformed.exitCode, 3);
    assert.equal(await readFile(path.join(reportDir, "findings.json"), "utf8"), "[]\n");
  });

  it("binds an audit commit only when it matches a clean recorded scan", async () => {
    const commit = "a".repeat(40);
    const other = "b".repeat(40);
    const legacy = resolveAuditCommitBinding({ git: undefined });
    const unbound = resolveAuditCommitBinding({ git: { commit, dirty: false } });
    const matchedBinding = resolveAuditCommitBinding({
      git: { commit, dirty: false },
      targetCommit: commit,
    });
    const mismatchBinding = resolveAuditCommitBinding({
      git: { commit, dirty: false },
      targetCommit: other,
    });
    const dirtyBinding = resolveAuditCommitBinding({
      git: { commit, dirty: true },
      targetCommit: commit,
    });
    const missingGit = resolveAuditCommitBinding({ git: undefined, targetCommit: commit });
    assert.equal(legacy.ok && legacy.binding, "legacy-scan");
    assert.equal(unbound.ok && unbound.binding, "unbound");
    assert.equal(matchedBinding.ok && matchedBinding.binding, "matched");
    assert.equal(mismatchBinding.ok, false);
    assert.equal(dirtyBinding.ok, false);
    assert.equal(missingGit.ok, false);
    if (!mismatchBinding.ok) assert.match(mismatchBinding.message, /does not match/);
    if (!dirtyBinding.ok) assert.match(dirtyBinding.message, /dirty worktree/);
    if (!missingGit.ok) assert.match(missingGit.message, /did not record a Git commit/);

    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-commit-bind-"));
    const reportDir = await copyMinimalScan(repo);
    const manifest = JSON.parse(await readFile(path.join(reportDir, "scan-manifest.json"), "utf8")) as ScanManifest;
    manifest.repositoryPath = await realpath(repo);
    manifest.git = { commit, dirty: false };
    await writeFile(path.join(reportDir, "scan-manifest.json"), `${JSON.stringify(manifest)}\n`);

    const mismatch = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: samplePath,
      targetCommit: other,
    });
    assert.equal(mismatch.ok, false);
    assert.equal(mismatch.exitCode, 3);
    assert.equal(await readFile(path.join(reportDir, "findings.json"), "utf8"), "[]\n");

    const matched = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: samplePath,
      targetCommit: commit,
    });
    assert.equal(matched.ok, true, matched.message);
    const attached = JSON.parse(await readFile(path.join(reportDir, "scan-manifest.json"), "utf8")) as ScanManifest;
    assert.equal(attached.sourceAudit?.commitBinding, "matched");
    assert.equal(attached.sourceAudit?.targetCommit, commit);
    const beforeRepeat = JSON.parse(await readFile(path.join(reportDir, "findings.json"), "utf8")) as unknown[];
    const repeated = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: samplePath,
      targetCommit: commit,
    });
    assert.equal(repeated.ok, true, repeated.message);
    const again = JSON.parse(await readFile(path.join(reportDir, "findings.json"), "utf8")) as unknown[];
    assert.equal(again.length, beforeRepeat.length);
    assert.equal(again.length, 2);
    const sarif = JSON.parse(await readFile(path.join(reportDir, "findings.sarif.json"), "utf8")) as {
      runs: Array<{ results: unknown[] }>;
    };
    assert.equal(sarif.runs[0]?.results.length, again.length);
    const repeatedManifest = JSON.parse(await readFile(path.join(reportDir, "scan-manifest.json"), "utf8")) as ScanManifest;
    assert.equal(repeatedManifest.sourceAudit?.commitBinding, "matched");
    assert.equal(repeatedManifest.sourceAudit?.commitIdentity?.agreement, "attested-matches-scan");
    assert.match(repeatedManifest.sourceAudit?.note ?? "", /not proof the audit executed/);
  });

  it("treats an identity sidecar as agent-attested and rejects contradictions", async () => {
    const commit = "c".repeat(40);
    const other = "d".repeat(40);
    assert.equal(auditIdentitySidecarPath("/tmp/findings.json"), "/tmp/findings.identity.json");
    assert.throws(() => parseAttestedAuditIdentity({ version: 1, extra: true }), /Unknown audit identity field/);
    assert.throws(() => parseAttestedAuditIdentity({ version: 2 }), /version must be 1/);
    const dirty = resolveAuditCommitBinding({
      git: { commit, dirty: false },
      attested: { commit, dirty: true, repositoryPath: null },
    });
    assert.equal(dirty.ok, false);
    const disagree = resolveAuditCommitBinding({
      git: { commit, dirty: false },
      targetCommit: commit,
      attested: { commit: other, dirty: false, repositoryPath: null },
    });
    assert.equal(disagree.ok, false);

    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-identity-"));
    const reportDir = await copyMinimalScan(repo);
    const canonical = await realpath(repo);
    const manifest = JSON.parse(await readFile(path.join(reportDir, "scan-manifest.json"), "utf8")) as ScanManifest;
    manifest.repositoryPath = canonical;
    manifest.git = { commit, dirty: false };
    await writeFile(path.join(reportDir, "scan-manifest.json"), `${JSON.stringify(manifest)}\n`);
    const findingsCopy = path.join(repo, "hunt.json");
    await writeFile(findingsCopy, await readFile(samplePath, "utf8"));
    await writeFile(
      auditIdentitySidecarPath(findingsCopy),
      `${JSON.stringify({ version: 1, repositoryPath: canonical, commit, dirty: false })}\n`,
    );
    const attached = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: findingsCopy,
    });
    assert.equal(attached.ok, true, attached.message);
    const saved = JSON.parse(await readFile(path.join(reportDir, "scan-manifest.json"), "utf8")) as ScanManifest;
    assert.equal(saved.sourceAudit?.commitBinding, "matched");
    assert.equal(saved.sourceAudit?.commitIdentity?.agreement, "attested-matches-scan");
    assert.equal(saved.sourceAudit?.commitIdentity?.attested?.commit, commit);
    const before = await readFile(path.join(reportDir, "findings.json"), "utf8");
    await writeFile(
      auditIdentitySidecarPath(findingsCopy),
      `${JSON.stringify({ version: 1, commit: other, dirty: false, repositoryPath: canonical })}\n`,
    );
    const rejected = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: findingsCopy,
      targetCommit: commit,
    });
    assert.equal(rejected.ok, false);
    assert.equal(rejected.exitCode, 3);
    assert.equal(await readFile(path.join(reportDir, "findings.json"), "utf8"), before);
    await writeFile(auditIdentitySidecarPath(findingsCopy), "{not-json\n");
    const malformed = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: findingsCopy,
    });
    assert.equal(malformed.ok, false);
    assert.equal(malformed.exitCode, 3);
    assert.equal(await readFile(path.join(reportDir, "findings.json"), "utf8"), before);
  });

  it("does not follow a report-directory symlink outside the repository", async () => {
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-symlink-report-"));
    const outside = await mkdtemp(path.join(os.tmpdir(), "security-scan-outside-"));
    await symlink(outside, path.join(repo, "escaped"));
    const result = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: path.join(repo, "escaped"),
      sourceAuditFindingsPath: samplePath,
    });
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 3);
    assert.match(result.message, /symlink/i);
    assert.deepEqual(await readdir(outside), []);
    await rm(outside, { recursive: true, force: true });
  });
});

async function copyMinimalScan(repo: string): Promise<string> {
  const source = path.join(fixtureDir, "fixtures/minimal-scan");
  const reportDir = path.join(repo, "security-reports", "fixture-scan");
  await mkdir(reportDir, { recursive: true });
  for (const name of ["findings.json", "profile.json", "scan-plan.json", "scan-manifest.json", "report.md"]) {
    await cp(path.join(source, name), path.join(reportDir, name));
  }
  const manifest = JSON.parse(await readFile(path.join(reportDir, "scan-manifest.json"), "utf8")) as {
    repositoryPath: string;
    reportDirectory: string;
  };
  manifest.repositoryPath = await realpath(repo);
  manifest.reportDirectory = reportDir;
  await writeFile(path.join(reportDir, "scan-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return reportDir;
}

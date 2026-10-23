import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import {
  buildSemgrepArgs,
  buildTrivyArgs,
  containerSourcePath,
  createAdapters,
  finalizeToolExecution,
  readSemgrepDocument,
  readTrivyDocument,
} from "../src/adapters.js";
import { createFinding } from "../src/findings.js";
import { assertNoEscapingSymlinks } from "../src/profile.js";
import { runSecurityScan, scanExitCode } from "../src/scanner.js";
import type { CanonicalFinding } from "../src/types.js";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function sampleFinding(): CanonicalFinding {
  return createFinding({
    title: "Fixture",
    severity: "high",
    category: "sast",
    component: null,
    location: { path: "app.py", startLine: 1 },
    evidence: "eval(cmd)",
    source: { tool: "semgrep", ruleId: "fixture.python.eval" },
    scannedAt: "2026-01-01T00:00:00.000Z",
  });
}

describe("orchestration failure and scope contracts", () => {
  it("keeps Semgrep exit 1 findings and rejects malformed or failed output", () => {
    const finding = sampleFinding();
    const completed = finalizeToolExecution({
      family: "semgrep",
      exitCode: 1,
      timedOut: false,
      documentValid: true,
      findings: [finding],
    });
    assert.equal(completed.status, "findings");
    assert.equal(completed.findings.length, 1);
    assert.equal(completed.exitCode, 1);

    const crashed = finalizeToolExecution({
      family: "semgrep",
      exitCode: 2,
      timedOut: false,
      documentValid: true,
      findings: [finding],
    });
    assert.equal(crashed.status, "failed");
    assert.deepEqual(crashed.findings, []);

    const emptyExit = finalizeToolExecution({
      family: "semgrep",
      exitCode: 1,
      timedOut: false,
      documentValid: true,
      findings: [],
    });
    assert.equal(emptyExit.status, "failed");

    const malformed = readTrivyDocument({});
    assert.equal(malformed.valid, false);
    const falseSuccess = finalizeToolExecution({
      family: "trivy",
      exitCode: 0,
      timedOut: false,
      documentValid: false,
      ...(malformed.error ? { documentError: malformed.error } : {}),
      findings: [],
    });
    assert.equal(falseSuccess.status, "failed");
    assert.equal(readTrivyDocument({ Results: [] }).valid, true);
    assert.equal(readSemgrepDocument({ results: [], errors: [{ message: "bad rule" }] }).valid, false);

    const timedOut = finalizeToolExecution({
      family: "trivy",
      exitCode: 0,
      timedOut: true,
      documentValid: true,
      findings: [finding],
    });
    assert.equal(timedOut.status, "failed");
    assert.deepEqual(timedOut.findings, []);

    const dart = finalizeToolExecution({
      family: "dart-analyze",
      exitCode: 3,
      timedOut: false,
      documentValid: true,
      findings: [finding],
    });
    assert.equal(dart.status, "findings");
    assert.equal(dart.exitCode, 3);
    const dartCrash = finalizeToolExecution({
      family: "dart-analyze",
      exitCode: 3,
      timedOut: false,
      documentValid: true,
      findings: [],
    });
    assert.equal(dartCrash.status, "failed");
  });

  it("maps scan status to the exit-code contract", () => {
    const finding = sampleFinding();
    assert.equal(scanExitCode("complete", [], "high"), 0);
    assert.equal(scanExitCode("complete_with_findings", [finding], "high"), 1);
    assert.equal(scanExitCode("incomplete", [finding], "high"), 2);
    assert.equal(scanExitCode("configuration_error", [], "high"), 3);
    finding.severity = "unknown";
    assert.equal(scanExitCode("complete_with_findings", [finding], "high"), 0);
  });

  it("passes exclude patterns as single arguments", () => {
    const malicious = "$(rm -rf /)";
    const trivy = buildTrivyArgs("trivy.json", [malicious], false);
    assert.equal(trivy.filter((argument) => argument === malicious).length, 1);
    assert.ok(trivy.includes("vuln,secret,misconfig"));
    assert.equal(trivy.at(-1), "/src");
    const semgrep = buildSemgrepArgs({
      outputName: "semgrep.json",
      exclude: [malicious],
      offline: true,
      checks: ["bundled-flutter-security"],
      targetPath: "mobile",
    });
    assert.equal(semgrep.filter((argument) => argument === malicious).length, 1);
    assert.ok(!semgrep.includes("p/default"));
    assert.ok(semgrep.includes("/rules/flutter-security.yml"));
    assert.equal(semgrep.at(-1), "/src/mobile");
    assert.throws(() => containerSourcePath("../outside"), /escapes/);
    assert.throws(() => buildTrivyArgs("../out.json", [], false), /Unsafe scanner output/);
  });

  it("does not install Dart packages when the workspace is unresolved", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "security-scan-dart-"));
    const dart = createAdapters().get("dart-analyze");
    assert.ok(dart);
    const reason = await dart.checkPrerequisites(
      {
        id: "dart-analyze-root",
        adapter: "dart-analyze",
        componentId: "root",
        targetPath: ".",
        required: false,
        checks: ["dart-static-analysis"],
        reason: "fixture",
      },
      {
        repoPath: root,
        rawDirectory: root,
        composeFile: path.join(projectRoot, "compose/security-scan.compose.yml"),
        offline: false,
        timeoutMs: 1_000,
        exclude: [],
      },
    );
    assert.match(reason ?? "", /package_config.json/);
    await assert.rejects(() => import("node:fs/promises").then((fs) => fs.access(path.join(root, ".dart_tool"))));
  });

  it("refuses an escaping symlink and an empty plan before running scanners", async () => {
    const linked = await mkdtemp(path.join(os.tmpdir(), "security-scan-linked-"));
    const outside = await mkdtemp(path.join(os.tmpdir(), "security-scan-link-target-"));
    await symlink(outside, path.join(linked, "outside"));
    await assert.rejects(() => runSecurityScan({ repo: linked, timeoutMs: 1_000 }), /symlink escapes/);
    await assert.rejects(() => assertNoEscapingSymlinks(linked), /symlink escapes/);

    const internal = await mkdtemp(path.join(os.tmpdir(), "security-scan-internal-link-"));
    await writeFile(path.join(internal, "README.md"), "ok\n");
    await symlink(path.join(internal, "README.md"), path.join(internal, "README.link"));
    await assertNoEscapingSymlinks(internal);

    const empty = await mkdtemp(path.join(os.tmpdir(), "security-scan-empty-plan-"));
    await writeFile(
      path.join(empty, ".security-scan.json"),
      JSON.stringify({ version: 1, tools: { trivy: { enabled: false }, semgrep: { enabled: false } } }),
    );
    await assert.rejects(
      () => runSecurityScan({ repo: empty, timeoutMs: 1_000 }),
      /No scanner was planned/,
    );
  });

  it("returns exit code 3 for invalid CLI arguments and unsafe scope", () => {
    const missing = runCli(["scan"]);
    assert.equal(missing.status, 3);
    const unknown = runCli(["nope", "--repo", projectRoot]);
    assert.equal(unknown.status, 3);
    const badSeverity = runCli(["scan", "--repo", projectRoot, "--fail-on", "banana"]);
    assert.equal(badSeverity.status, 3);
    const badJobs = runCli(["scan", "--repo", projectRoot, "--jobs", "0"]);
    assert.equal(badJobs.status, 3);
    const version = runCli(["version"]);
    assert.equal(version.status, 0);
    assert.match(version.stdout, /0\.3\.2/);
    const fileTarget = runCli(["profile", "--repo", path.join(projectRoot, "package.json")]);
    assert.equal(fileTarget.status, 3);
  });

  it("rejects a report directory that is a symlink to another directory", async () => {
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-report-link-"));
    const outside = await mkdtemp(path.join(os.tmpdir(), "security-scan-report-outside-"));
    await mkdir(path.join(repo, "src"), { recursive: true });
    await writeFile(path.join(repo, "src", "app.py"), "print('ok')\n");
    await symlink(outside, path.join(repo, "security-reports"));
    await assert.rejects(() => runSecurityScan({ repo, timeoutMs: 1_000 }), /symlink escapes/);
  });
});

function runCli(args: string[]) {
  return spawnSync(process.execPath, ["--import", "tsx", path.join(projectRoot, "src/cli.ts"), ...args], {
    cwd: projectRoot,
    encoding: "utf8",
  });
}

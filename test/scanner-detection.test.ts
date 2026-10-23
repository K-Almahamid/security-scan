import assert from "node:assert/strict";
import { cp, mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { createAdapters, finalizeToolExecution, parseSemgrep, parseTrivy } from "../src/adapters.js";
import { allowedHostEnvironment, runCommand, runComposeTool } from "../src/execution.js";
import type { AdapterContext, ToolPlan } from "../src/types.js";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sources = path.join(projectRoot, "test/fixtures/sources");
const requireDocker = process.env.SECURITY_SCAN_REQUIRE_DOCKER === "1";

async function dockerComposeAvailable(): Promise<boolean> {
  try {
    const result = await runCommand("docker", ["info"], {
      cwd: projectRoot,
      timeoutMs: 15_000,
      env: allowedHostEnvironment(),
    });
    return result.exitCode === 0;
  } catch {
    return false;
  }
}

function requireOrSkip(available: boolean, reason: string): void {
  if (available) return;
  if (requireDocker) throw new Error(reason);
  throw new SkipSignal(reason);
}

class SkipSignal extends Error {}

describe("pinned scanner detection", { timeout: 300_000 }, () => {
  it("Semgrep production adapter detects the bundled Flutter rule and not the clean file", async (t) => {
    try {
      requireOrSkip(await dockerComposeAvailable(), "Docker Compose is required for scanner detection");
    } catch (error) {
      if (error instanceof SkipSignal) {
        t.skip(error.message);
        return;
      }
      throw error;
    }
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-flutter-"));
    const raw = await mkdtemp(path.join(os.tmpdir(), "security-scan-flutter-raw-"));
    await cp(path.join(sources, "main.dart"), path.join(repo, "main.dart"));
    await cp(path.join(sources, "clean.dart"), path.join(repo, "clean.dart"));
    const plan: ToolPlan = {
      id: "semgrep-mobile",
      adapter: "semgrep",
      componentId: "mobile",
      targetPath: ".",
      required: true,
      checks: ["dart", "bundled-flutter-security"],
      reason: "fixture",
    };
    const context: AdapterContext = {
      repoPath: repo,
      rawDirectory: raw,
      composeFile: path.join(projectRoot, "compose/security-scan.compose.yml"),
      offline: true,
      timeoutMs: 180_000,
      exclude: [],
    };
    const adapter = createAdapters().get("semgrep");
    assert.ok(adapter);
    assert.equal(await adapter.checkPrerequisites(plan, context), null);
    const result = await adapter.execute(plan, context);
    assert.equal(result.run.status, "findings", result.run.reason ?? "semgrep adapter failed");
    assert.ok(result.run.exitCode === 0 || result.run.exitCode === 1);
    const matched = result.findings.filter((finding) =>
      finding.sources.some((source) => source.ruleId.includes("sensitive-debug-output")),
    );
    assert.equal(matched.length, 1);
    assert.equal(matched[0]?.location.path, "main.dart");
    assert.ok(!result.findings.some((finding) => finding.location.path === "clean.dart"));
    assert.equal(matched[0]?.provenance, "deterministic");
  });

  it("pinned Semgrep fixture rules detect eval and dangerous HTML, including exit code 1", async (t) => {
    try {
      requireOrSkip(await dockerComposeAvailable(), "Docker Compose is required for scanner detection");
    } catch (error) {
      if (error instanceof SkipSignal) {
        t.skip(error.message);
        return;
      }
      throw error;
    }
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-rules-"));
    const raw = await mkdtemp(path.join(os.tmpdir(), "security-scan-rules-raw-"));
    for (const name of ["app.py", "clean.py", "page.tsx", "clean.tsx"]) {
      await cp(path.join(sources, name), path.join(repo, name));
    }
    await cp(path.join(projectRoot, "test/fixtures/rules/fixture-rules.yml"), path.join(repo, "fixture-rules.yml"));
    const result = await runComposeTool({
      composeFile: path.join(projectRoot, "compose/security-scan.compose.yml"),
      service: "semgrep",
      repoPath: repo,
      rawDirectory: raw,
      timeoutMs: 180_000,
      args: [
        "semgrep",
        "scan",
        "--metrics=off",
        "--disable-version-check",
        "--error",
        "--json",
        "--output",
        "/out/local.json",
        "--config",
        "/src/fixture-rules.yml",
        "/src",
      ],
    });
    assert.equal(result.exitCode, 1, result.stderr || result.stdout);
    const document = JSON.parse(await readFile(path.join(raw, "local.json"), "utf8")) as unknown;
    const findings = parseSemgrep(document, repo, null);
    const completion = finalizeToolExecution({
      family: "semgrep",
      exitCode: result.exitCode,
      timedOut: result.timedOut,
      documentValid: true,
      findings,
    });
    assert.equal(completion.status, "findings");
    assert.deepEqual(
      completion.findings.map((finding) => finding.sources[0]?.ruleId).sort(),
      ["fixture.python.eval", "fixture.react.dangerous-html"],
    );
    assert.deepEqual(
      completion.findings.map((finding) => finding.location.path).sort(),
      ["app.py", "page.tsx"],
    );
  });

  it("pinned Trivy detects a synthetic token and USER root, not the clean fixtures", async (t) => {
    try {
      requireOrSkip(await dockerComposeAvailable(), "Docker Compose is required for scanner detection");
    } catch (error) {
      if (error instanceof SkipSignal) {
        t.skip(error.message);
        return;
      }
      throw error;
    }
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-trivy-"));
    const raw = await mkdtemp(path.join(os.tmpdir(), "security-scan-trivy-raw-"));
    const canary = `ghp_${"FAKE".repeat(9)}1234`;
    await writeFile(path.join(repo, "canary.env"), `GITHUB_TOKEN=${canary}\n`);
    await writeFile(path.join(repo, "clean.env"), "APP_NAME=fixture\nLOG_LEVEL=info\n");
    await cp(path.join(sources, "Dockerfile"), path.join(repo, "Dockerfile"));
    await cp(path.join(sources, "Dockerfile.clean"), path.join(repo, "Dockerfile.clean"));
    const result = await runComposeTool({
      composeFile: path.join(projectRoot, "compose/security-scan.compose.yml"),
      service: "trivy",
      repoPath: repo,
      rawDirectory: raw,
      timeoutMs: 180_000,
      args: [
        "fs",
        "--skip-version-check",
        "--scanners",
        "secret,misconfig",
        "--skip-db-update",
        "--format",
        "json",
        "--output",
        "/out/trivy.json",
        "/src",
      ],
    });
    assert.equal(result.exitCode, 0, result.stderr || result.stdout);
    const document = JSON.parse(await readFile(path.join(raw, "trivy.json"), "utf8")) as unknown;
    const findings = parseTrivy(document, repo, null);
    const completion = finalizeToolExecution({
      family: "trivy",
      exitCode: result.exitCode,
      timedOut: false,
      documentValid: true,
      findings,
    });
    assert.equal(completion.status, "findings");
    const secret = completion.findings.find(
      (finding) => finding.category === "secret" && finding.sources[0]?.ruleId === "github-pat",
    );
    assert.equal(secret?.location.path, "canary.env");
    assert.ok(!secret?.evidence.redacted.includes(canary));
    assert.ok(!completion.findings.some((finding) => finding.location.path === "clean.env"));
    const rootUser = completion.findings.filter(
      (finding) => finding.sources[0]?.ruleId === "DS002",
    );
    assert.deepEqual(rootUser.map((finding) => finding.location.path), ["Dockerfile"]);
    assert.equal(rootUser[0]?.dependency, undefined);
  });
});

describe("dart analyzer detection", () => {
  it("reports an undefined function from an already resolved workspace and stays quiet on an empty main", async (t) => {
    const version = await runCommand("dart", ["--version"], {
      cwd: projectRoot,
      timeoutMs: 15_000,
      env: allowedHostEnvironment(),
    }).catch(() => null);
    if (!version || version.exitCode !== 0) {
      t.skip("Dart SDK is not installed; this does not establish analyzer detection");
      return;
    }
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-dart-scan-"));
    await mkdir(path.join(repo, "lib"), { recursive: true });
    await writeFile(
      path.join(repo, "pubspec.yaml"),
      'name: fixture_app\nenvironment:\n  sdk: ">=3.0.0 <4.0.0"\n',
    );
    await writeFile(path.join(repo, "lib/bad.dart"), "void main() {\n  missingFunction();\n}\n");
    await writeFile(path.join(repo, "lib/clean.dart"), "void main() {}\n");
    const pub = await runCommand("dart", ["pub", "get"], {
      cwd: repo,
      timeoutMs: 60_000,
      env: allowedHostEnvironment(),
    });
    assert.equal(pub.exitCode, 0);
    const raw = await mkdtemp(path.join(os.tmpdir(), "security-scan-dart-raw-"));
    const adapter = createAdapters().get("dart-analyze");
    assert.ok(adapter);
    const context: AdapterContext = {
      repoPath: repo,
      rawDirectory: raw,
      composeFile: path.join(projectRoot, "compose/security-scan.compose.yml"),
      offline: false,
      timeoutMs: 60_000,
      exclude: [],
    };
    const badPlan: ToolPlan = {
      id: "dart-bad",
      adapter: "dart-analyze",
      componentId: "root",
      targetPath: ".",
      required: false,
      checks: ["dart-static-analysis"],
      reason: "fixture",
    };
    assert.equal(await adapter.checkPrerequisites(badPlan, context), null);
    const badRaw = path.join(raw, "bad");
    await mkdir(badRaw, { recursive: true });
    const badRun = await adapter.execute(badPlan, { ...context, rawDirectory: badRaw });
    assert.equal(badRun.run.status, "findings");
    assert.equal(badRun.run.exitCode, 3);
    assert.ok(badRun.findings.some((finding) => finding.sources[0]?.ruleId === "UNDEFINED_FUNCTION"));
    assert.ok(badRun.findings.some((finding) => finding.location.path?.endsWith("lib/bad.dart")));

    const cleanRepo = await mkdtemp(path.join(os.tmpdir(), "security-scan-dart-clean-"));
    await mkdir(path.join(cleanRepo, "lib"), { recursive: true });
    await writeFile(
      path.join(cleanRepo, "pubspec.yaml"),
      'name: fixture_clean\nenvironment:\n  sdk: ">=3.0.0 <4.0.0"\n',
    );
    await writeFile(path.join(cleanRepo, "lib/clean.dart"), "void main() {}\n");
    const cleanPub = await runCommand("dart", ["pub", "get"], {
      cwd: cleanRepo,
      timeoutMs: 60_000,
      env: allowedHostEnvironment(),
    });
    assert.equal(cleanPub.exitCode, 0);
    const cleanRaw = path.join(raw, "clean");
    await mkdir(cleanRaw, { recursive: true });
    const clean = await adapter.execute(
      { ...badPlan, id: "dart-clean" },
      { ...context, repoPath: cleanRepo, rawDirectory: cleanRaw },
    );
    assert.equal(clean.run.status, "passed");
    assert.equal(clean.findings.length, 0);
  });
});

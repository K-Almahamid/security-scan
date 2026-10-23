import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";
import { defaultConfig, loadConfig } from "../src/config.js";
import { buildScanPlan } from "../src/planner.js";
import { assertNoEscapingSymlinks, profileRepository } from "../src/profile.js";
import { coverageSummary } from "../src/reports.js";

const roots: string[] = [];

async function fixtureRoot(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "security-scan-profile-"));
  roots.push(root);
  return root;
}

after(async () => {
  await Promise.all(roots.map((root) => rm(root, { recursive: true, force: true })));
});

describe("repository profiler and planner", () => {
  it("detects a FastAPI, Next.js, and Flutter monorepo", async () => {
    const root = await fixtureRoot();
    await mkdir(path.join(root, "api"), { recursive: true });
    await mkdir(path.join(root, "web"), { recursive: true });
    await mkdir(path.join(root, "mobile", ".dart_tool"), { recursive: true });
    await writeFile(
      path.join(root, "api", "pyproject.toml"),
      '[project]\ndependencies = ["fastapi>=1"]\n',
    );
    await writeFile(path.join(root, "api", "main.py"), "from fastapi import FastAPI\n");
    await writeFile(
      path.join(root, "web", "package.json"),
      JSON.stringify({ dependencies: { next: "16.0.0", react: "19.0.0" } }),
    );
    await writeFile(path.join(root, "web", "package-lock.json"), "{}");
    await writeFile(path.join(root, "web", "page.tsx"), "export default function Page() {}");
    await writeFile(
      path.join(root, "mobile", "pubspec.yaml"),
      "dependencies:\n  flutter:\n    sdk: flutter\n",
    );
    await writeFile(path.join(root, "mobile", "pubspec.lock"), "packages: {}\n");
    await writeFile(path.join(root, "mobile", "main.dart"), "void main() {}\n");
    await writeFile(path.join(root, "mobile", ".dart_tool", "package_config.json"), "{}");
    await writeFile(path.join(root, "Dockerfile"), "FROM scratch\n");
    await mkdir(path.join(root, "compose"));
    await writeFile(path.join(root, "compose", "security-scan.compose.yml"), "services: {}\n");

    const profile = await profileRepository(root, defaultConfig, new Date("2026-01-01T00:00:00Z"));
    assert.equal(profile.components.length, 3);
    assert.deepEqual(
      profile.components.map((component) => component.frameworks),
      [["fastapi"], ["flutter"], ["nextjs", "react"]],
    );
    assert.equal(
      profile.components.find((component) => component.path === "mobile")
        ?.hasExistingDartWorkspace,
      true,
    );
    assert.deepEqual(profile.dockerfiles, ["Dockerfile"]);
    assert.deepEqual(profile.composeFiles, ["compose/security-scan.compose.yml"]);

    const plan = buildScanPlan(profile, defaultConfig);
    assert.equal(plan.tools.filter((tool) => tool.adapter === "trivy").length, 1);
    assert.equal(plan.tools.filter((tool) => tool.adapter === "semgrep").length, 3);
    assert.equal(plan.tools.filter((tool) => tool.adapter === "dart-analyze").length, 1);
    assert.ok(plan.outOfScope.some((gap) => gap.includes("MobSF")));
    assert.deepEqual(plan.coverageGaps, plan.unsupported);
  });

  it("does not follow symlinked directories", async () => {
    const root = await fixtureRoot();
    await writeFile(path.join(root, "package.json"), JSON.stringify({ dependencies: {} }));
    const { symlink } = await import("node:fs/promises");
    await symlink(os.homedir(), path.join(root, "outside"));
    const profile = await profileRepository(root, defaultConfig);
    assert.equal(profile.components.length, 1);
    await assert.rejects(() => assertNoEscapingSymlinks(root), /symlink escapes/);
  });

  it("records previous manifests, plans Trivy for container files, and leaves Rust unsupported", async () => {
    const root = await fixtureRoot();
    await mkdir(path.join(root, "security-reports", "old-scan"), { recursive: true });
    await writeFile(path.join(root, "security-reports", "old-scan", "scan-manifest.json"), "{}\n");
    await writeFile(path.join(root, "security-reports", "old-scan", "notes.txt"), "not source\n");
    await writeFile(path.join(root, "Dockerfile"), "FROM scratch\n");
    await writeFile(path.join(root, "docker-compose.yml"), "services: {}\n");
    await writeFile(path.join(root, "lib.rs"), "fn main() {}\n");
    const profile = await profileRepository(root, defaultConfig);
    assert.deepEqual(profile.previousReports, ["security-reports/old-scan/scan-manifest.json"]);
    assert.deepEqual(profile.dockerfiles, ["Dockerfile"]);
    assert.deepEqual(profile.composeFiles, ["docker-compose.yml"]);
    const plan = buildScanPlan(profile, defaultConfig);
    assert.deepEqual(plan.tools.map((tool) => tool.adapter), ["trivy"]);
    assert.ok(plan.unsupported.some((entry) => entry.includes("rust")));
    const coverage = coverageSummary(plan, []);
    assert.equal(coverage.comprehensive, false);
    assert.equal(coverage.plannedStatus, "partial");
    assert.ok(!coverage.plannedChecks.some((check) => check.startsWith("semgrep:")));
  });

  it("plans Semgrep for Python source that only has a requirements file", async () => {
    const root = await fixtureRoot();
    await writeFile(path.join(root, "requirements.txt"), "fastapi==0.0.0\n");
    await writeFile(path.join(root, "app.py"), "print('ok')\n");
    const profile = await profileRepository(root, defaultConfig);
    assert.deepEqual(profile.components[0]?.languages, ["python"]);
    assert.deepEqual(profile.components[0]?.lockfiles, ["requirements.txt"]);
    const plan = buildScanPlan(profile, defaultConfig);
    assert.equal(plan.tools.filter((tool) => tool.adapter === "semgrep").length, 1);
  });

  it("rejects allowFailedTools because it would hide an incomplete scan", async () => {
    const root = await fixtureRoot();
    await writeFile(
      path.join(root, ".security-scan.json"),
      JSON.stringify({ version: 1, policy: { allowFailedTools: true } }),
    );
    await assert.rejects(() => loadConfig(root), /allowFailedTools/);
  });
});

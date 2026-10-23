import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";
import { defaultConfig } from "../src/config.js";
import { buildScanPlan } from "../src/planner.js";
import { profileRepository } from "../src/profile.js";

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
  });
});

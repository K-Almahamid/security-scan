import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { createAdapters } from "../src/adapters.js";
import { defaultConfig, loadConfig } from "../src/config.js";
import { buildScanPlan } from "../src/planner.js";
import { profileRepository } from "../src/profile.js";
import {
  assertValidCapabilityRegistry,
  evaluateCapabilityReadiness,
  getCapabilityById,
  getCapabilityRegistry,
  planCapability,
  planScanFromRegistry,
  resolveCapabilityToggle,
} from "../src/registry.js";

const EXPECTED_CAPABILITY_IDS = [
  "trivy.repository",
  "semgrep.component",
  "dart-analyze.component",
];

describe("capability registry", () => {
  it("contains the existing scanner capabilities with stable ids", () => {
    assertValidCapabilityRegistry();
    const registry = getCapabilityRegistry();
    assert.deepEqual(registry.map((capability) => capability.id), EXPECTED_CAPABILITY_IDS);
    assert.equal(getCapabilityById("trivy.repository")?.adapter, "trivy");
    assert.equal(getCapabilityById("semgrep.component")?.focus, "security");
    assert.equal(getCapabilityById("dart-analyze.component")?.focus, "code-quality");
  });

  it("maps every capability to a registered adapter", () => {
    const adapters = createAdapters();
    for (const capability of getCapabilityRegistry()) {
      assert.ok(adapters.has(capability.adapter), capability.id);
    }
  });

  it("rejects duplicate capability ids during validation", () => {
    const ids = getCapabilityRegistry().map((capability) => capability.id);
    assert.equal(new Set(ids).size, ids.length);
    for (const id of ids) {
      assert.match(id, /^[a-z0-9][a-z0-9.-]*$/);
    }
  });

  it("treats enabled auto as evidence-based for Semgrep", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "security-scan-registry-auto-"));
    await writeFile(path.join(root, "lib.rs"), "fn main() {}\n");
    const profile = await profileRepository(root, defaultConfig);
    const semgrep = getCapabilityById("semgrep.component");
    assert.ok(semgrep);
    const component = profile.components[0];
    assert.ok(component);
    const autoPlan = planCapability(semgrep, profile, defaultConfig, component);
    assert.equal(autoPlan.state, "unsupported");
    assert.equal(planScanFromRegistry(profile, defaultConfig).tools.length, 1);
    assert.equal(planScanFromRegistry(profile, defaultConfig).tools[0]?.adapter, "trivy");
  });

  it("keeps explicitly disabled capabilities out of the scan plan", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "security-scan-registry-disabled-"));
    await writeFile(path.join(root, "app.py"), "print('ok')\n");
    await writeFile(
      path.join(root, ".security-scan.json"),
      JSON.stringify({
        version: 1,
        tools: {
          trivy: { enabled: false, offline: false },
          semgrep: { enabled: false },
          dartAnalyze: { enabled: false },
        },
      }),
    );
    const config = await loadConfig(root);
    const profile = await profileRepository(root, config);
    const plan = buildScanPlan(profile, config);
    assert.equal(plan.tools.length, 0);
    assert.ok(plan.outOfScope.some((entry) => entry.includes("Trivy repository checks disabled")));
    assert.ok(plan.outOfScope.some((entry) => entry.includes("Semgrep checks disabled")));
  });

  it("does not treat enabled true as a substitute for project evidence when auto would skip", () => {
    assert.equal(resolveCapabilityToggle("auto", false), false);
    assert.equal(resolveCapabilityToggle("auto", true), true);
    assert.equal(resolveCapabilityToggle(true, false), true);
    assert.equal(resolveCapabilityToggle(false, true), false);
  });

  it("reports capability readiness states for doctor output", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "security-scan-registry-doctor-"));
    await writeFile(path.join(root, "app.py"), "print('ok')\n");
    const profile = await profileRepository(root, defaultConfig);
    const plan = buildScanPlan(profile, defaultConfig);
    const readiness = evaluateCapabilityReadiness({
      profile,
      config: defaultConfig,
      plan,
      prerequisites: {
        "docker-compose": false,
        "dart-sdk": false,
      },
    });
    const trivy = readiness.find((entry) => entry.capabilityId === "trivy.repository");
    assert.ok(trivy);
    assert.equal(trivy.category, "required");
    assert.equal(trivy.status, "fail");
    const dartEntries = readiness.filter((entry) => entry.capabilityId.startsWith("dart-analyze"));
    assert.ok(dartEntries.every((entry) => entry.status === "skip"));
  });

  it("preserves representative scan plans after the registry refactor", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "security-scan-registry-monorepo-"));
    const { mkdir } = await import("node:fs/promises");
    await mkdir(path.join(root, "api"), { recursive: true });
    await writeFile(path.join(root, "api", "main.py"), "print('ok')\n");
    await writeFile(path.join(root, "api", "pyproject.toml"), '[project]\nname="api"\n');
    const profile = await profileRepository(root, defaultConfig);
    const plan = buildScanPlan(profile, defaultConfig);
    assert.ok(plan.tools.some((tool) => tool.id === "trivy-repository"));
    assert.ok(plan.tools.some((tool) => tool.adapter === "semgrep"));
  });
});

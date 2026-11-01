import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { findCapabilityRegistryError, getCapabilityRegistry } from "../src/registry.js";
import { dispatchTool } from "../src/scanner.js";
import type { AdapterContext, ToolAdapter, ToolPlan } from "../src/types.js";

describe("scanner extension", () => {
  it("rejects an unknown adapter and runs a registered fake scanner", async () => {
    const error = findCapabilityRegistryError([
      {
        ...getCapabilityRegistry()[0]!,
        id: "fixture.scanner",
        adapter: "not-a-scanner" as ToolPlan["adapter"],
      },
    ]);
    assert.match(error ?? "", /unknown adapter/);

    const plan: ToolPlan = {
      id: "fixture",
      adapter: "trivy",
      componentId: null,
      targetPath: ".",
      required: true,
      checks: ["fixture"],
      reason: "test",
    };
    const fake: ToolAdapter = {
      id: "trivy",
      checkPrerequisites: async () => null,
      execute: async (toolPlan) => ({
        findings: [],
        run: {
          id: toolPlan.id,
          adapter: toolPlan.adapter,
          componentId: null,
          status: "passed",
          startedAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
          durationMs: 1,
          exitCode: 0,
          version: "fixture",
          reason: null,
          logPath: null,
          findingCount: 0,
          discardedDuringParse: 0,
        },
      }),
    };
    const context = {
      repoPath: process.cwd(),
      rawDirectory: process.cwd(),
      composeFile: "unused",
      offline: true,
      timeoutMs: 1_000,
      exclude: [],
    } satisfies AdapterContext;
    const ran = await dispatchTool(new Map([["trivy", fake]]), plan, context);
    assert.equal(ran.run.status, "passed");
    assert.equal(ran.run.version, "fixture");
    const missing = await dispatchTool(new Map(), { ...plan, adapter: "gitleaks" }, context);
    assert.equal(missing.run.status, "unsupported");
  });
});

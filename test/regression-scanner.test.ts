import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseTrivy } from "../src/adapters.js";
import { createFinding, redactSensitiveText, severityAtOrAbove } from "../src/findings.js";
import { determineOverallStatus } from "../src/reports.js";
import type { ToolRun } from "../src/types.js";

describe("scanner regression fixtures", () => {
  it("detects a synthetic secret from mocked Trivy output", () => {
    const findings = parseTrivy(
      {
        Results: [
          {
            Target: "config.env",
            Secrets: [
              {
                RuleID: "aws-access-key-id",
                Severity: "CRITICAL",
                Title: "AWS Access Key",
                StartLine: 2,
                EndLine: 2,
                Match: "AKIAIOSFODNN7EXAMPLE",
              },
            ],
          },
        ],
      },
      "/tmp/repo",
      null,
    );
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.category, "secret");
  });

  it("returns no findings for a clean mocked Trivy result", () => {
    const findings = parseTrivy(
      { Results: [{ Target: "README.md", Vulnerabilities: [] }] },
      "/tmp/repo",
      null,
    );
    assert.equal(findings.length, 0);
  });

  it("marks required tool failure as incomplete rather than complete", () => {
    const runs: ToolRun[] = [
      {
        id: "trivy-repo",
        adapter: "trivy",
        componentId: null,
        status: "failed",
        startedAt: "2026-01-01T00:00:00.000Z",
        completedAt: "2026-01-01T00:00:00.000Z",
        durationMs: 1,
        exitCode: 1,
        version: null,
        reason: "timeout",
        logPath: null,
        findingCount: 0,
      },
    ];
    assert.equal(determineOverallStatus(runs, []), "incomplete");
  });

  it("handles malformed scanner output without throwing", () => {
    const findings = parseTrivy({}, "/tmp/repo", null);
    assert.deepEqual(findings, []);
  });

  it("redacts secrets in normalized evidence", () => {
    const finding = createFinding({
      title: "token leak",
      severity: "high",
      category: "secret",
      component: null,
      location: { path: ".env", startLine: 1 },
      evidence: "token=super-secret sk-abcdefghijklmnopqrstuvwxyz",
      source: { tool: "trivy", ruleId: "generic-secret" },
    });
    assert.ok(!finding.evidence.redacted.includes("super-secret"));
    assert.match(redactSensitiveText("Bearer abc.def.ghi"), /REDACTED/);
  });

  it("applies severity threshold semantics for exit decisions", () => {
    assert.equal(severityAtOrAbove("high", "high"), true);
    assert.equal(severityAtOrAbove("medium", "high"), false);
    assert.equal(severityAtOrAbove("unknown", "high"), false);
  });
});

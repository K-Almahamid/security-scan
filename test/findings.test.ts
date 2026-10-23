import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createFinding,
  deduplicateFindings,
  normalizeSeverity,
  redactSensitiveText,
} from "../src/findings.js";

describe("finding normalization and deduplication", () => {
  it("redacts common credential forms without retaining values", () => {
    const input =
      "token=super-secret-value Authorization: Bearer abc.def.ghi sk-abcdefghijklmnop";
    const output = redactSensitiveText(input);
    assert.ok(!output.includes("super-secret-value"));
    assert.ok(!output.includes("abc.def.ghi"));
    assert.ok(!output.includes("sk-abcdefghijklmnop"));
    assert.match(output, /REDACTED/);
    assert.equal(normalizeSeverity("fatal"), "unknown");
    assert.equal(normalizeSeverity("note"), "info");
  });

  it("merges evidence-equivalent findings and preserves sources", () => {
    const base = {
      title: "Unsafe query",
      severity: "high" as const,
      category: "sast" as const,
      component: "api",
      location: { path: "app/query.py", startLine: 10, endLine: 10 },
      evidence: "execute(user_input)",
      cwe: ["CWE-89"],
      scannedAt: "2026-01-01T00:00:00.000Z",
    };
    const semgrep = createFinding({
      ...base,
      source: { tool: "semgrep", ruleId: "semgrep.python.sql-injection" },
    });
    const codeql = createFinding({
      ...base,
      source: { tool: "codeql", ruleId: "codeql.python.sql-injection" },
    });
    const deduped = deduplicateFindings([semgrep, codeql]);
    assert.equal(deduped.length, 1);
    assert.equal(deduped[0]?.sources.length, 2);
  });

  it("does not merge same-title findings at different locations", () => {
    const first = createFinding({
      title: "Hardcoded secret",
      severity: "high",
      category: "secret",
      component: null,
      location: { path: "a.env", startLine: 1 },
      evidence: "token=first-secret",
      source: { tool: "trivy", ruleId: "token" },
    });
    const second = createFinding({
      title: "Hardcoded secret",
      severity: "high",
      category: "secret",
      component: null,
      location: { path: "b.env", startLine: 1 },
      evidence: "token=second-secret",
      source: { tool: "trivy", ruleId: "token" },
    });
    assert.equal(deduplicateFindings([first, second]).length, 2);
  });

  it("consolidates Trivy and Semgrep missing-USER findings without evidence loss", () => {
    const trivy = createFinding({
      title: "Image user should not be root",
      severity: "high",
      category: "misconfiguration",
      component: null,
      location: { path: "api/Dockerfile" },
      evidence: "Specify a non-root USER",
      source: { tool: "trivy", ruleId: "DS002" },
    });
    const semgrep = createFinding({
      title: "Dockerfile has no USER",
      severity: "medium",
      category: "sast",
      component: "api",
      location: { path: "api/Dockerfile", startLine: 25, endLine: 25 },
      evidence: {
        text: "CMD [\"server\"]",
        kind: "code",
      },
      source: {
        tool: "semgrep",
        ruleId: "dockerfile.security.missing-user.missing-user",
      },
      cwe: ["CWE-250"],
    });

    const deduped = deduplicateFindings([trivy, semgrep]);
    assert.equal(deduped.length, 1);
    assert.equal(deduped[0]?.sources.length, 2);
    assert.deepEqual(
      deduped[0]?.sources.map((source) => source.severity),
      ["high", "medium"],
    );
    assert.equal(deduped[0]?.sources[0]?.location?.path, "api/Dockerfile");
    assert.equal(deduped[0]?.sources[1]?.location?.startLine, 25);
    assert.equal(deduped[0]?.sources[0]?.evidence?.redacted, "Specify a non-root USER");
    assert.equal(deduped[0]?.sources[1]?.evidence?.redacted, "CMD [\"server\"]");
    assert.equal(deduped[0]?.component, "api");
  });

  it("groups related HTTP sinks but retains each location", () => {
    const makeSink = (startLine: number, evidence: string) =>
      createFinding({
        title: "Unencrypted request over HTTP",
        severity: "high",
        category: "sast",
        component: "web",
        location: { path: "scripts/verify.mjs", startLine, endLine: startLine + 2 },
        evidence,
        source: {
          tool: "semgrep",
          ruleId: "typescript.react.security.react-insecure-request.react-insecure-request",
        },
      });
    const deduped = deduplicateFindings([
      makeSink(12, "fetch(loginUrl)"),
      makeSink(60, "fetch(categoriesUrl)"),
      makeSink(67, "fetch(productsUrl)"),
    ]);

    assert.equal(deduped.length, 3);
    assert.equal(new Set(deduped.map((finding) => finding.dedupe.relatedGroupId)).size, 1);
    assert.deepEqual(
      deduped.map((finding) => finding.location.startLine),
      [12, 60, 67],
    );
    assert.deepEqual(
      deduped.map((finding) => finding.sources[0]?.evidence?.redacted),
      ["fetch(loginUrl)", "fetch(categoriesUrl)", "fetch(productsUrl)"],
    );
  });

  it("keeps distinct CVEs for the same dependency separate", () => {
    const makeCve = (cve: string) =>
      createFinding({
        title: cve,
        severity: "high",
        category: "sca",
        component: null,
        cve: [cve],
        location: {
          path: "package-lock.json",
          package: "@grpc/grpc-js",
          installedVersion: "1.9.16",
        },
        evidence: "@grpc/grpc-js 1.9.16",
        source: { tool: "trivy", ruleId: cve },
      });

    assert.equal(
      deduplicateFindings([
        makeCve("CVE-2026-101915"),
        makeCve("CVE-2026-101916"),
      ]).length,
      2,
    );
  });

  it("keeps a stable fingerprint for equivalent inputs and preserves unknown severity", () => {
    const input = {
      title: "Missing excerpt",
      severity: "unknown" as const,
      category: "sast" as const,
      component: null,
      location: {},
      evidence: "",
      source: { tool: "semgrep", ruleId: "rule.without.location" },
      scannedAt: "2026-01-01T00:00:00.000Z",
    };
    const first = createFinding(input);
    const second = createFinding({
      ...input,
      source: { tool: "semgrep", ruleId: "rule.other" },
    });
    assert.equal(first.fingerprint, createFinding(input).fingerprint);
    assert.equal(first.severity, "unknown");
    assert.equal(deduplicateFindings([first, second]).length, 2);
    assert.equal(first.dependency, undefined);
  });
});

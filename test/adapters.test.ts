import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  parseDartAnalyze,
  parseSemgrep,
  parseTrivy,
} from "../src/adapters.js";

describe("tool output adapters", () => {
  it("normalizes Trivy vulnerabilities, secrets, and misconfigurations", () => {
    const findings = parseTrivy(
      {
        Results: [
          {
            Target: "package-lock.json",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-2026-0001",
                PkgName: "demo",
                InstalledVersion: "1.0.0",
                FixedVersion: "1.0.1",
                Severity: "HIGH",
                Title: "Demo issue",
                PrimaryURL: "https://example.test/advisories/CVE-2026-0001",
              },
            ],
            Secrets: [
              {
                RuleID: "generic-token",
                Title: "Token",
                Severity: "HIGH",
                StartLine: 4,
                Match: "token=very-secret-value",
              },
            ],
            Misconfigurations: [
              {
                ID: "DS001",
                Title: "Container runs as root",
                Severity: "MEDIUM",
                Message: "No USER instruction",
                CauseMetadata: { StartLine: 1, EndLine: 1 },
              },
            ],
          },
        ],
      },
      "/repo",
      null,
    );
    assert.equal(findings.length, 3);
    assert.deepEqual(
      findings.map((finding) => finding.category).sort(),
      ["misconfiguration", "sca", "secret"],
    );
    assert.ok(!findings.find((finding) => finding.category === "secret")?.evidence.redacted.includes("very-secret-value"));
    const dependency = findings.find((finding) => finding.category === "sca")?.dependency;
    assert.equal(dependency?.presence, "confirmed");
    assert.equal(dependency?.reachability, "not_analyzed");
    assert.equal(dependency?.advisorySource, "https://example.test/advisories/CVE-2026-0001");
    assert.equal(dependency?.publisherVerification, "not_performed");
  });

  it("normalizes Semgrep source locations and CWE", () => {
    const findings = parseSemgrep(
      {
        results: [
          {
            check_id: "python.lang.security.audit.eval",
            path: "/src/api/app.py",
            start: { line: 7 },
            end: { line: 7 },
            extra: {
              message: "Avoid eval",
              severity: "ERROR",
              lines: "eval(user_input)",
              metadata: { cwe: ["CWE-95"], confidence: "HIGH" },
            },
          },
        ],
      },
      "/repo",
      "api",
    );
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.location.path, "api/app.py");
    assert.equal(findings[0]?.severity, "high");
    assert.deepEqual(findings[0]?.cwe, ["CWE-95"]);
    assert.equal(findings[0]?.evidence.kind, "code");
  });

  it("explains unavailable Semgrep evidence instead of presenting requires-login text", () => {
    const findings = parseSemgrep(
      {
        results: [{
          check_id: "dockerfile.security.missing-user.missing-user",
          path: "/src/api/Dockerfile",
          start: { line: 25 },
          end: { line: 25 },
          extra: {
            message: "Missing USER",
            severity: "ERROR",
            lines: "requires login",
            metadata: {},
          },
        }],
      },
      "/repo",
      "api",
    );
    assert.equal(findings[0]?.evidence.kind, "unavailable");
    assert.ok(!findings[0]?.evidence.redacted.includes("requires login"));
    assert.match(findings[0]?.evidence.limitation ?? "", /authenticated access/);
    assert.match(findings[0]?.evidence.redacted ?? "", /api\/Dockerfile:25/);
  });

  it("handles missing and malformed Semgrep evidence explicitly", () => {
    const base = {
      check_id: "javascript.security.rule",
      path: "/src/web/app.ts",
      start: { line: 2 },
      end: { line: 2 },
    };
    const findings = parseSemgrep(
      {
        results: [
          { ...base, extra: { message: "Missing", severity: "WARNING", metadata: {} } },
          {
            ...base,
            start: { line: 3 },
            end: { line: 3 },
            extra: { message: "Malformed", severity: "WARNING", lines: { text: "x" }, metadata: {} },
          },
        ],
      },
      "/repo",
      "web",
    );
    assert.match(findings[0]?.evidence.limitation ?? "", /did not provide/);
    assert.match(findings[1]?.evidence.limitation ?? "", /malformed/);
  });

  it("redacts credentials in Semgrep code evidence", () => {
    const findings = parseSemgrep(
      {
        results: [{
          check_id: "javascript.security.hardcoded-password",
          path: "/src/web/test.ts",
          start: { line: 4 },
          end: { line: 4 },
          extra: {
            message: "Hardcoded password",
            severity: "ERROR",
            lines: 'const password = "DoNotExposeThis123!";',
            metadata: {},
          },
        }],
      },
      "/repo",
      "web",
    );
    assert.equal(findings[0]?.evidence.kind, "redacted");
    assert.ok(!findings[0]?.evidence.redacted.includes("DoNotExposeThis123!"));
  });

  it("normalizes Dart analyzer machine output", () => {
    const findings = parseDartAnalyze(
      "WARNING|STATIC_WARNING|avoid_print|/repo/lib/main.dart|3|1|5|Avoid print calls",
      "/repo",
      "mobile",
    );
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.location.path, "lib/main.dart");
    assert.equal(findings[0]?.severity, "medium");
  });
});

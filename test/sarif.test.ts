import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createFinding } from "../src/findings.js";
import { canonicalFindingsToSarif } from "../src/reports.js";

describe("SARIF export", () => {
  it("writes a SARIF 2.1.0 result without copying redacted evidence", () => {
    const finding = createFinding({
      title: "Possible secret",
      severity: "high",
      category: "secret",
      component: null,
      location: { path: "src/a.ts", startLine: 2 },
      evidence: { text: "token super-secret-value", kind: "redacted" },
      source: { tool: "gitleaks", ruleId: "generic-api-key" },
    });
    const sarif = canonicalFindingsToSarif([finding]);
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs[0]?.results[0]?.ruleId, "generic-api-key");
    assert.equal(sarif.runs[0]?.results[0]?.level, "error");
    assert.equal(sarif.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri, "src/a.ts");
    assert.equal(sarif.runs[0]?.results[0]?.partialFingerprints.primary, finding.fingerprint);
    assert.equal(JSON.stringify(sarif).includes("super-secret-value"), false);
  });
});

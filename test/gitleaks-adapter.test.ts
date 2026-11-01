import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseGitleaksDocument } from "../src/adapters.js";

describe("gitleaks adapter", () => {
  it("redacts secret values and counts malformed rows", () => {
    const secret = "super-secret-value-do-not-keep";
    const parsed = parseGitleaksDocument(
      [
        {
          Description: "Generic API key",
          File: "src/app.ts",
          StartLine: 4,
          RuleID: "generic-api-key",
          Secret: secret,
          Match: secret,
        },
        { File: "" },
        "not-a-row",
      ],
      "/repo",
    );
    assert.equal(parsed.findings.length, 1);
    assert.equal(parsed.discarded, 2);
    assert.equal(parsed.findings[0]?.location.path, "src/app.ts");
    assert.equal(parsed.findings[0]?.evidence.kind, "redacted");
    assert.equal(JSON.stringify(parsed).includes(secret), false);
    const invalid = parseGitleaksDocument({ findings: [] }, "/repo");
    assert.equal(invalid.discarded, 1);
    assert.equal(invalid.findings.length, 0);
  });
});

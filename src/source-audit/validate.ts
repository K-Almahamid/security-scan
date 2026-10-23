import { spawn } from "node:child_process";
import { cloudflareValidatorPath } from "./paths.js";

export interface SourceAuditValidationResult {
  ok: boolean;
  exitCode: number;
  output: string;
}

export async function validateCloudflareFindingsFile(
  findingsPath: string,
): Promise<SourceAuditValidationResult> {
  const validator = cloudflareValidatorPath();
  return await new Promise((resolve) => {
    const child = spawn(process.execPath, [validator, findingsPath], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (chunk: Buffer) => {
      output += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      output += chunk.toString("utf8");
    });
    child.on("close", (code) => {
      const exitCode = code ?? 1;
      resolve({
        ok: exitCode === 0,
        exitCode,
        output: output.trim(),
      });
    });
    child.on("error", (error) => {
      resolve({
        ok: false,
        exitCode: 4,
        output: error.message,
      });
    });
  });
}

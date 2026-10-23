import { readFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";

const toolToggleSchema = z.object({ enabled: z.union([z.boolean(), z.literal("auto")]).default("auto") });

export const configSchema = z
  .object({
    $schema: z.string().optional(),
    version: z.literal(1).default(1),
    reportsDir: z.string().default("security-reports"),
    components: z
      .array(
        z.object({
          path: z.string().min(1).refine(
            (value) =>
              !path.isAbsolute(value) &&
              !value.split(/[\\/]/).some((segment) => segment === ".."),
            "Component paths must remain inside the target repository",
          ),
        }),
      )
      .default([]),
    exclude: z
      .array(z.string())
      .default(["**/node_modules/**", "**/.venv/**", "**/.next/**", "**/dist/**"]),
    tools: z
      .object({
        trivy: toolToggleSchema
          .extend({ offline: z.boolean().default(false) })
          .default({ enabled: "auto", offline: false }),
        semgrep: toolToggleSchema.default({ enabled: "auto" }),
        dartAnalyze: toolToggleSchema.default({ enabled: "auto" }),
      })
      .default({
        trivy: { enabled: "auto", offline: false },
        semgrep: { enabled: "auto" },
        dartAnalyze: { enabled: "auto" },
      }),
    policy: z
      .object({
        failOn: z.enum(["critical", "high", "medium", "low", "info"]).default("high"),
        allowFailedTools: z.boolean().default(false),
      })
      .default({ failOn: "high", allowFailedTools: false }),
  })
  .strict();

export type SecurityScanConfig = z.infer<typeof configSchema>;

export const defaultConfig: SecurityScanConfig = configSchema.parse({});

export async function loadConfig(
  repoPath: string,
  explicitPath?: string,
): Promise<SecurityScanConfig> {
  const configPath = explicitPath ?? path.join(repoPath, ".security-scan.json");
  try {
    const text = await readFile(configPath, "utf8");
    const parsed: unknown = JSON.parse(text);
    assertNoCredentialKeys(parsed);
    return configSchema.parse(parsed);
  } catch (error) {
    if (
      !explicitPath &&
      error instanceof Error &&
      "code" in error &&
      error.code === "ENOENT"
    ) {
      return defaultConfig;
    }
    throw error;
  }
}

function assertNoCredentialKeys(value: unknown, trail = "config"): void {
  if (!value || typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    if (/(password|secret|token|api.?key|credential|authorization)/i.test(key)) {
      throw new Error(`Credential-bearing config key is forbidden: ${trail}.${key}`);
    }
    assertNoCredentialKeys(nested, `${trail}.${key}`);
  }
}

export function resolveReportsDirectory(repoPath: string, configured: string): string {
  const resolved = path.resolve(repoPath, configured);
  const relative = path.relative(repoPath, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("reportsDir must remain inside the target repository");
  }
  return resolved;
}

import type { SecurityScanConfig } from "./config.js";
import type { RepositoryProfile, ScanPlan, ToolPlan } from "./types.js";

const semgrepLanguages = new Set([
  "dart",
  "python",
  "typescript",
  "javascript",
  "go",
  "java",
  "kotlin",
]);

export function buildScanPlan(
  profile: RepositoryProfile,
  config: SecurityScanConfig,
): ScanPlan {
  const tools: ToolPlan[] = [];
  const unsupported: string[] = [];
  const outOfScope = [
    "Dynamic application security testing (DAST) and arbitrary remote target scanning",
    "Active penetration testing or exploit execution",
    "Authenticated runtime testing against local, staging, or production environments",
    "Comprehensive mobile security testing such as MobSF or a full MASVS assessment",
    "Built container-image and runtime operating-system package scanning",
  ];
  const supportedChecks = [
    "Repository dependency vulnerability analysis",
    "Repository secret detection",
    "Docker, Compose, and supported configuration misconfiguration analysis",
    "Semgrep CE static analysis for supported source languages",
    "Dart analyzer checks for already-resolved workspaces",
  ];

  if (config.tools.trivy.enabled !== false) {
    tools.push({
      id: "trivy-repository",
      adapter: "trivy",
      componentId: null,
      targetPath: ".",
      required: true,
      checks: ["vulnerability", "secret", "misconfiguration"],
      reason: "Repository-wide dependencies, secrets, Docker, Compose, IaC, and configuration",
    });
  } else {
    outOfScope.push("Trivy repository checks disabled by target configuration");
  }

  for (const component of profile.components) {
    const supportsSemgrep = component.languages.some((language) => semgrepLanguages.has(language));
    if (config.tools.semgrep.enabled !== false && supportsSemgrep) {
      tools.push({
        id: `semgrep-${component.id}`,
        adapter: "semgrep",
        componentId: component.id,
        targetPath: component.path,
        required: true,
        checks: selectSemgrepChecks(component.languages, component.frameworks),
        reason: `Static analysis for ${[...component.languages, ...component.frameworks].join(", ")}`,
      });
    } else if (component.languages.length > 0 && !supportsSemgrep) {
      unsupported.push(
        `${component.id}: no configured Semgrep coverage for ${component.languages.join(", ")}`,
      );
    } else if (config.tools.semgrep.enabled === false && supportsSemgrep) {
      outOfScope.push(`${component.id}: Semgrep checks disabled by target configuration`);
    }

    if (component.languages.includes("dart") && config.tools.dartAnalyze.enabled !== false) {
      tools.push({
        id: `dart-analyze-${component.id}`,
        adapter: "dart-analyze",
        componentId: component.id,
        targetPath: component.path,
        required: false,
        checks: ["dart-static-analysis"],
        reason: component.hasExistingDartWorkspace
          ? "Existing Dart workspace can be analyzed without dependency installation"
          : "Dart workspace has no existing package configuration; adapter will report skipped",
      });
    } else if (
      component.languages.includes("dart") &&
      config.tools.dartAnalyze.enabled === false
    ) {
      outOfScope.push(`${component.id}: Dart analyzer disabled by target configuration`);
    }
  }

  return {
    mode: "standard",
    tools,
    supportedChecks,
    outOfScope: [...new Set(outOfScope)],
    unsupported,
    coverageGaps: unsupported,
  };
}

function selectSemgrepChecks(languages: string[], frameworks: string[]): string[] {
  const checks = new Set<string>(["security-audit"]);
  for (const language of languages) checks.add(language);
  for (const framework of frameworks) checks.add(framework);
  if (languages.includes("dart")) checks.add("bundled-flutter-security");
  return [...checks].sort();
}

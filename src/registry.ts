import type { SecurityScanConfig } from "./config.js";
import type { ComponentProfile, RepositoryProfile, ScanPlan, ToolPlan } from "./types.js";

const KNOWN_ADAPTERS = new Set<ToolPlan["adapter"]>(["trivy", "semgrep", "dart-analyze"]);

export type CapabilityPrerequisite = "docker-compose" | "dart-sdk";

export type CapabilityConfigKey = keyof SecurityScanConfig["tools"];

export type CapabilityFocus = "security" | "code-quality";

export type CapabilityPlanningState =
  | "not_applicable"
  | "disabled"
  | "scheduled"
  | "unsupported";

export interface CapabilityDefinition {
  id: string;
  name: string;
  purpose: string;
  adapter: ToolPlan["adapter"];
  focus: CapabilityFocus;
  configKey: CapabilityConfigKey;
  scope: "repository" | "component";
  prerequisites: CapabilityPrerequisite[];
  /** When scheduled in the scan plan, is the tool run marked required? */
  requiredWhenScheduled: boolean;
  isAutoApplicable(profile: RepositoryProfile, component?: ComponentProfile): boolean;
  isApplicable(profile: RepositoryProfile, component?: ComponentProfile): boolean;
  buildToolPlan(input: {
    profile: RepositoryProfile;
    component?: ComponentProfile;
  }): ToolPlan;
}

export interface CapabilityPlanningResult {
  capabilityId: string;
  state: CapabilityPlanningState;
  toolPlan: ToolPlan | null;
  note: string | null;
}

export interface CapabilityReadiness {
  capabilityId: string;
  name: string;
  category: "required" | "optional";
  status: "pass" | "fail" | "warn" | "skip";
  planningState: CapabilityPlanningState;
  message: string;
}

const SEMGREP_LANGUAGES = new Set([
  "dart",
  "python",
  "typescript",
  "javascript",
  "go",
  "java",
  "kotlin",
]);

const STATIC_OUT_OF_SCOPE = [
  "Dynamic application security testing (DAST) and arbitrary remote target scanning",
  "Active penetration testing or exploit execution",
  "Authenticated runtime testing against local, staging, or production environments",
  "Comprehensive mobile security testing such as MobSF or a full MASVS assessment",
  "Built container-image and runtime operating-system package scanning",
];

const STATIC_SUPPORTED_CHECKS = [
  "Repository dependency vulnerability analysis",
  "Repository secret detection",
  "Docker, Compose, and supported configuration misconfiguration analysis",
  "Semgrep CE static analysis for supported source languages",
  "Dart analyzer checks for already-resolved workspaces",
];

const CAPABILITY_DEFINITIONS: CapabilityDefinition[] = [
  {
    id: "trivy.repository",
    name: "Trivy repository scan",
    purpose:
      "Dependency vulnerabilities, secrets, and supported misconfigurations across the repository tree.",
    adapter: "trivy",
    focus: "security",
    configKey: "trivy",
    scope: "repository",
    prerequisites: ["docker-compose"],
    requiredWhenScheduled: true,
    isAutoApplicable: () => true,
    isApplicable: () => true,
    buildToolPlan: () => ({
      id: "trivy-repository",
      adapter: "trivy",
      componentId: null,
      targetPath: ".",
      required: true,
      checks: ["vulnerability", "secret", "misconfiguration"],
      reason: "Repository-wide dependencies, secrets, Docker, Compose, IaC, and configuration",
    }),
  },
  {
    id: "semgrep.component",
    name: "Semgrep CE static analysis",
    purpose: "Static application security testing for supported source languages per component.",
    adapter: "semgrep",
    focus: "security",
    configKey: "semgrep",
    scope: "component",
    prerequisites: ["docker-compose"],
    requiredWhenScheduled: true,
    isAutoApplicable: (_profile, component) =>
      Boolean(component?.languages.some((language) => SEMGREP_LANGUAGES.has(language))),
    isApplicable: (_profile, component) => Boolean(component && component.languages.length > 0),
    buildToolPlan: ({ component }) => {
      if (!component) throw new Error("semgrep.component requires a component profile");
      return {
        id: `semgrep-${component.id}`,
        adapter: "semgrep",
        componentId: component.id,
        targetPath: component.path,
        required: true,
        checks: selectSemgrepChecks(component.languages, component.frameworks),
        reason: `Static analysis for ${[...component.languages, ...component.frameworks].join(", ")}`,
      };
    },
  },
  {
    id: "dart-analyze.component",
    name: "Dart analyzer",
    purpose:
      "Static analysis for Dart workspaces that already have a resolved package configuration.",
    adapter: "dart-analyze",
    focus: "code-quality",
    configKey: "dartAnalyze",
    scope: "component",
    prerequisites: ["dart-sdk"],
    requiredWhenScheduled: false,
    isAutoApplicable: (_profile, component) => Boolean(component?.languages.includes("dart")),
    isApplicable: (_profile, component) => Boolean(component?.languages.includes("dart")),
    buildToolPlan: ({ component }) => {
      if (!component) throw new Error("dart-analyze.component requires a component profile");
      return {
        id: `dart-analyze-${component.id}`,
        adapter: "dart-analyze",
        componentId: component.id,
        targetPath: component.path,
        required: false,
        checks: ["dart-static-analysis"],
        reason: component.hasExistingDartWorkspace
          ? "Existing Dart workspace can be analyzed without dependency installation"
          : "Dart workspace has no existing package configuration; adapter will report skipped",
      };
    },
  },
];

let registryValidated = false;

export function getCapabilityRegistry(): readonly CapabilityDefinition[] {
  assertValidCapabilityRegistry();
  return CAPABILITY_DEFINITIONS;
}

export function getCapabilityById(id: string): CapabilityDefinition | undefined {
  return getCapabilityRegistry().find((capability) => capability.id === id);
}

export function assertValidCapabilityRegistry(): void {
  if (registryValidated) return;
  const ids = new Set<string>();
  for (const capability of CAPABILITY_DEFINITIONS) {
    if (ids.has(capability.id)) {
      throw new Error(`Duplicate capability id: ${capability.id}`);
    }
    ids.add(capability.id);
    if (!KNOWN_ADAPTERS.has(capability.adapter)) {
      throw new Error(`Capability ${capability.id} references unknown adapter: ${capability.adapter}`);
    }
    if (!/^[a-z0-9][a-z0-9.-]*$/.test(capability.id)) {
      throw new Error(`Invalid capability id: ${capability.id}`);
    }
  }
  registryValidated = true;
}

export function resolveCapabilityToggle(
  toggle: boolean | "auto",
  autoApplicable: boolean,
): boolean {
  if (toggle === false) return false;
  if (toggle === true) return true;
  return autoApplicable;
}

export function planCapability(
  capability: CapabilityDefinition,
  profile: RepositoryProfile,
  config: SecurityScanConfig,
  component?: ComponentProfile,
): CapabilityPlanningResult {
  if (capability.scope === "component" && !component) {
    return {
      capabilityId: capability.id,
      state: "not_applicable",
      toolPlan: null,
      note: null,
    };
  }
  if (!capability.isApplicable(profile, component)) {
    return {
      capabilityId: capability.id,
      state: "not_applicable",
      toolPlan: null,
      note: null,
    };
  }

  const toggle = config.tools[capability.configKey].enabled;
  const autoApplicable = capability.isAutoApplicable(profile, component);

  if (toggle === false) {
    return {
      capabilityId: capability.id,
      state: "disabled",
      toolPlan: null,
      note: disabledConfigurationNote(capability, component),
    };
  }

  if (!autoApplicable) {
    if (capability.id === "semgrep.component" && component && component.languages.length > 0) {
      return {
        capabilityId: capability.id,
        state: "unsupported",
        toolPlan: null,
        note: `${component.id}: no configured Semgrep coverage for ${component.languages.join(", ")}`,
      };
    }
    return {
      capabilityId: capability.id,
      state: "not_applicable",
      toolPlan: null,
      note: null,
    };
  }

  const shouldSchedule = toggle === true || (toggle === "auto" && autoApplicable);
  if (!shouldSchedule) {
    return {
      capabilityId: capability.id,
      state: "not_applicable",
      toolPlan: null,
      note: null,
    };
  }

  return {
    capabilityId: capability.id,
    state: "scheduled",
    toolPlan: capability.buildToolPlan({
      profile,
      ...(component ? { component } : {}),
    }),
    note: null,
  };
}

export function planScanFromRegistry(
  profile: RepositoryProfile,
  config: SecurityScanConfig,
): ScanPlan {
  assertValidCapabilityRegistry();
  const tools: ToolPlan[] = [];
  const unsupported: string[] = [];
  const outOfScope = [...STATIC_OUT_OF_SCOPE];
  for (const capability of CAPABILITY_DEFINITIONS) {
    if (capability.scope === "repository") {
      const result = planCapability(capability, profile, config);
      if (result.state === "scheduled" && result.toolPlan) tools.push(result.toolPlan);
      if (result.state === "disabled" && result.note) outOfScope.push(result.note);
      if (result.state === "unsupported" && result.note) unsupported.push(result.note);
      continue;
    }

    for (const component of profile.components) {
      const result = planCapability(capability, profile, config, component);
      if (result.state === "scheduled" && result.toolPlan) tools.push(result.toolPlan);
      if (result.state === "disabled" && result.note) outOfScope.push(result.note);
      if (result.state === "unsupported" && result.note) unsupported.push(result.note);
    }
  }

  return {
    mode: "standard",
    tools,
    supportedChecks: [...STATIC_SUPPORTED_CHECKS],
    outOfScope: [...new Set(outOfScope)],
    unsupported,
    coverageGaps: unsupported,
  };
}

export function evaluateCapabilityReadiness(input: {
  profile: RepositoryProfile;
  config: SecurityScanConfig;
  plan: ScanPlan;
  prerequisites: Partial<Record<CapabilityPrerequisite, boolean>>;
}): CapabilityReadiness[] {
  assertValidCapabilityRegistry();
  const results: CapabilityReadiness[] = [];

  for (const capability of CAPABILITY_DEFINITIONS) {
    if (capability.scope === "repository") {
      results.push(
        readinessForCapability(capability, input.profile, input.config, undefined, {
          scheduled: input.plan.tools.some((tool) => tool.adapter === capability.adapter),
          prerequisites: input.prerequisites,
        }),
      );
      continue;
    }

    for (const component of input.profile.components) {
      const compositeId = `${capability.id}@${component.id}`;
      const planning = planCapability(capability, input.profile, input.config, component);
      const scheduled = input.plan.tools.some(
        (tool) => tool.id === capability.buildToolPlan({ profile: input.profile, component }).id,
      );
      const readiness = readinessForCapability(
        capability,
        input.profile,
        input.config,
        component,
        {
          scheduled,
          prerequisites: input.prerequisites,
          planningState: planning.state,
          checkId: compositeId,
        },
      );
      results.push(readiness);
    }
  }

  return results;
}

function readinessForCapability(
  capability: CapabilityDefinition,
  profile: RepositoryProfile,
  config: SecurityScanConfig,
  component: ComponentProfile | undefined,
  context: {
    scheduled: boolean;
    prerequisites: Partial<Record<CapabilityPrerequisite, boolean>>;
    planningState?: CapabilityPlanningState;
    checkId?: string;
  },
): CapabilityReadiness {
  const planning =
    context.planningState ??
    planCapability(capability, profile, config, component).state;
  const checkId = context.checkId ?? capability.id;
  const componentLabel = component ? ` (${component.id})` : "";

  if (planning === "not_applicable") {
    return {
      capabilityId: checkId,
      name: capability.name,
      category: "optional",
      status: "skip",
      planningState: planning,
      message: `${capability.name}${componentLabel} is not applicable to the detected project.`,
    };
  }

  if (planning === "disabled") {
    return {
      capabilityId: checkId,
      name: capability.name,
      category: "optional",
      status: "skip",
      planningState: planning,
      message: `${capability.name}${componentLabel} is disabled by configuration.`,
    };
  }

  if (planning === "unsupported") {
    return {
      capabilityId: checkId,
      name: capability.name,
      category: "optional",
      status: "skip",
      planningState: planning,
      message: `${capability.name}${componentLabel} is not supported for the detected languages.`,
    };
  }

  const category = capability.requiredWhenScheduled ? "required" : "optional";
  const blocked = capability.prerequisites.find(
    (prerequisite) => context.prerequisites[prerequisite] === false,
  );

  if (!context.scheduled) {
    return {
      capabilityId: checkId,
      name: capability.name,
      category,
      status: "skip",
      planningState: "not_applicable",
      message: `${capability.name}${componentLabel} was not scheduled for this repository.`,
    };
  }

  if (blocked) {
    const message =
      blocked === "docker-compose"
        ? `${capability.name}${componentLabel} requires Docker Compose, which is unavailable.`
        : `${capability.name}${componentLabel} requires the Dart SDK on PATH, which is unavailable.`;
    return {
      capabilityId: checkId,
      name: capability.name,
      category,
      status: category === "required" ? "fail" : "warn",
      planningState: "scheduled",
      message,
    };
  }

  return {
    capabilityId: checkId,
    name: capability.name,
    category,
    status: "pass",
    planningState: "scheduled",
    message: `${capability.name}${componentLabel} is scheduled and prerequisites are available.`,
  };
}

function disabledConfigurationNote(
  capability: CapabilityDefinition,
  component?: ComponentProfile,
): string {
  if (capability.id === "trivy.repository") {
    return "Trivy repository checks disabled by target configuration";
  }
  if (capability.id === "semgrep.component" && component) {
    return `${component.id}: Semgrep checks disabled by target configuration`;
  }
  if (capability.id === "dart-analyze.component" && component) {
    return `${component.id}: Dart analyzer disabled by target configuration`;
  }
  const label = component ? `${component.id}: ` : "";
  return `${label}${capability.name} disabled by target configuration`;
}

export function selectSemgrepChecks(languages: string[], frameworks: string[]): string[] {
  const checks = new Set<string>(["security-audit"]);
  for (const language of languages) checks.add(language);
  for (const framework of frameworks) checks.add(framework);
  if (languages.includes("dart")) checks.add("bundled-flutter-security");
  return [...checks].sort();
}

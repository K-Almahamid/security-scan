export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";
export type Confidence = "high" | "medium" | "low";
export type FindingCategory = "sast" | "sca" | "secret" | "misconfiguration" | "quality";
export type FindingProvenance = "deterministic" | "source-audit";
export type AuditVerdict = "confirmed" | "needs_validation" | "rejected";
export type FindingVerification =
  | "confirmed"
  | "potential"
  | "not_verified"
  | "needs_validation"
  | "rejected";
export type ToolStatus = "passed" | "findings" | "skipped" | "failed" | "unsupported";
export type OverallStatus =
  | "complete"
  | "complete_with_findings"
  | "incomplete"
  | "configuration_error";

export interface ComponentProfile {
  id: string;
  path: string;
  languages: string[];
  frameworks: string[];
  lockfiles: string[];
  manifests: string[];
  hasExistingDartWorkspace: boolean;
}

export interface RepositoryProfile {
  repositoryPath: string;
  generatedAt: string;
  components: ComponentProfile[];
  dockerfiles: string[];
  composeFiles: string[];
  ciFiles: string[];
  previousReports: string[];
}

export interface ToolPlan {
  id: string;
  adapter: "trivy" | "semgrep" | "dart-analyze";
  componentId: string | null;
  targetPath: string;
  required: boolean;
  checks: string[];
  reason: string;
}

export interface ScanPlan {
  mode: "standard";
  tools: ToolPlan[];
  supportedChecks: string[];
  outOfScope: string[];
  unsupported: string[];
  /** @deprecated Read unsupported. Retained for v1 consumers. */
  coverageGaps: string[];
}

export interface FindingLocation {
  path?: string | undefined;
  startLine?: number | undefined;
  endLine?: number | undefined;
  endpoint?: string | undefined;
  package?: string | undefined;
  installedVersion?: string | undefined;
}

export interface FindingSource {
  tool: string;
  ruleId: string;
  rawId?: string | undefined;
  severity?: Severity | undefined;
  confidence?: Confidence | undefined;
  category?: FindingCategory | undefined;
  location?: FindingLocation | undefined;
  evidence?: FindingEvidence | undefined;
}

export interface FindingEvidence {
  redacted: string;
  ruleId: string;
  kind: "code" | "metadata" | "redacted" | "unavailable";
  limitation?: string | undefined;
}

export interface DependencyInterpretation {
  presence: "confirmed";
  reachability: "not_analyzed";
  advisorySource: string;
  advisoryCheckedAt: string;
  publisherVerification: "not_performed";
}

export interface CanonicalFinding {
  id: string;
  fingerprint: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  category: FindingCategory;
  cwe: string[];
  cve: string[];
  component: string | null;
  location: FindingLocation;
  evidence: FindingEvidence;
  sources: FindingSource[];
  dependency?: DependencyInterpretation | undefined;
  impact: string;
  remediation: string;
  verification: FindingVerification;
  provenance?: FindingProvenance | undefined;
  auditVerdict?: AuditVerdict | undefined;
  dedupe: {
    groupId: string;
    primary: boolean;
    relatedGroupId: string | null;
    relatedReason?: string | undefined;
  };
  firstSeen: string;
  scannedAt: string;
}

export interface ToolRun {
  id: string;
  adapter: string;
  componentId: string | null;
  status: ToolStatus;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  exitCode: number | null;
  version: string | null;
  reason: string | null;
  logPath: string | null;
  findingCount: number;
}

export interface SourceAuditAttachment {
  status: "attached" | "validation_failed";
  methodology: "cloudflare-security-audit-skill";
  upstreamCommit: string;
  sourceFindingsPath: string;
  validatedAt: string;
  orchestration: "cursor-agent";
  counts: Record<AuditVerdict, number>;
  note: string;
}

export interface ScanManifest {
  schemaVersion: 2;
  scanId: string;
  repositoryPath: string;
  startedAt: string;
  completedAt: string;
  overallStatus: OverallStatus;
  mode: "standard";
  toolRuns: ToolRun[];
  execution: {
    status: "complete" | "incomplete";
    planned: number;
    completed: number;
    failed: number;
    skipped: number;
    unsupported: number;
  };
  coverage: {
    comprehensive: false;
    plannedStatus: "complete" | "partial";
    plannedChecks: string[];
    supportedChecks: string[];
    outOfScope: string[];
    unsupported: string[];
  };
  /** @deprecated Read coverage.unsupported. Retained for v1 consumers. */
  coverageGaps: string[];
  counts: Record<Severity, number>;
  rawArtifactsPath: string;
  reportDirectory: string;
  sourceAudit?: SourceAuditAttachment | undefined;
}

export interface AdapterContext {
  repoPath: string;
  rawDirectory: string;
  composeFile: string;
  offline: boolean;
  timeoutMs: number;
  exclude: string[];
}

export interface AdapterResult {
  run: ToolRun;
  findings: CanonicalFinding[];
}

export interface ToolAdapter {
  readonly id: ToolPlan["adapter"];
  checkPrerequisites(plan: ToolPlan, context: AdapterContext): Promise<string | null>;
  execute(plan: ToolPlan, context: AdapterContext): Promise<AdapterResult>;
}

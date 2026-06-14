// Mirrors the analyzer's JSON contract (dev.pluginguard.engine.model.ScanResult).

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type Verdict =
  | "MINIMAL_RISK"
  | "LOW_RISK"
  | "MEDIUM_RISK"
  | "HIGH_RISK"
  | "CRITICAL_RISK";

export type Category =
  | "STRUCTURE"
  | "PLUGIN_YML"
  | "NETWORK"
  | "PROCESS"
  | "CLASS_LOADING"
  | "NATIVE"
  | "FILESYSTEM"
  | "CRYPTO"
  | "REFLECTION"
  | "SCRIPTING"
  | "DESERIALIZATION"
  | "SYSTEM"
  | "OBFUSCATION"
  | "STRING_IOC"
  | "SUPPLY_CHAIN"
  | "COMBO"
  | "MINECRAFT"
  | "MALWARE_SIGNATURE"
  | "RESOURCE_PACK"
  | "DATA_PACK"
  | "PROVENANCE";

/** Classified artifact kind — mirrors the analyzer's dev.pluginguard.engine.model.ArtifactType. */
export type ArtifactType =
  | "PLUGIN_BUKKIT"
  | "PLUGIN_BUNGEE"
  | "PLUGIN_VELOCITY"
  | "MOD_FORGE"
  | "MOD_NEOFORGE"
  | "MOD_FABRIC"
  | "MOD_QUILT"
  | "RESOURCE_PACK"
  | "DATA_PACK"
  | "UNKNOWN";

export interface Finding {
  ruleId: string;
  category: Category;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  location: string | null;
  evidence: string | null;
  scoreImpact: number;
  nestedPath: string | null;
  relatedRuleIds: string[];
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface PluginInfo {
  descriptorFile: string;
  name: string | null;
  version: string | null;
  main: string | null;
  apiVersion: string | null;
  authors: string[];
  commands: string[];
  permissions: string[];
  depend: string[];
  softDepend: string[];
  libraries: string[];
}

export interface Dependency {
  name: string;
  version: string | null;
  source: string;
}

export interface Summaries {
  network: string[];
  filesystem: string[];
  dependencies: Dependency[];
  classCount: number;
  methodCount: number;
}

export type SandboxStatus =
  | "DISABLED"
  | "PENDING"
  | "RUNNING"
  | "COMPLETED"
  | "SKIPPED"
  | "UNAVAILABLE"
  | "FAILED";

export type DynamicCorrelation = "CONFIRMS_STATIC" | "DYNAMIC_ONLY";

export interface BehaviorEvent {
  type: string;
  target: string | null;
  detail: string | null;
  source: string | null;
  blocked: boolean;
}

export interface DynamicFinding {
  ruleId: string;
  eventType: string;
  severity: Severity;
  title: string;
  target: string | null;
  blocked: boolean;
  occurrences: number;
  correlation: DynamicCorrelation;
  description: string;
  recommendation: string;
}

export interface SandboxReport {
  status: SandboxStatus;
  runner: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number;
  worstSeverity: Severity | null;
  behaviorEventCount: number;
  dynamicFindings: DynamicFinding[];
  behaviorEvents: BehaviorEvent[];
  caveats: string[];
  note: string | null;
}

export interface ScanResult {
  id: string;
  fileName: string;
  sha256: string;
  sizeBytes: number;
  platform: string;
  artifactType: ArtifactType;
  mainClass: string | null;
  mcApiVersion: string | null;
  score: number;
  verdict: Verdict;
  obfuscationScore: number;
  counts: SeverityCounts;
  pluginInfo: PluginInfo | null;
  findings: Finding[];
  summaries: Summaries;
  notes: string[];
  analyzedAt: string;
  durationMs: number;
  engineVersion: string;
  sandbox: SandboxReport | null;
}

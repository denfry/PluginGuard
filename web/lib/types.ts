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
  | "SYSTEM"
  | "OBFUSCATION"
  | "STRING_IOC"
  | "PROVENANCE";

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

export interface ScanResult {
  id: string;
  fileName: string;
  sha256: string;
  sizeBytes: number;
  platform: string;
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
}

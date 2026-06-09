import type { Category, Severity, Verdict } from "./types";

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`;
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  MINIMAL_RISK: "Minimal Risk",
  LOW_RISK: "Low Risk",
  MEDIUM_RISK: "Medium Risk",
  HIGH_RISK: "High Risk",
  CRITICAL_RISK: "Critical Risk",
};

/** Tailwind text colour for a verdict / score band. */
export function verdictColor(verdict: Verdict): string {
  switch (verdict) {
    case "MINIMAL_RISK":
    case "LOW_RISK":
      return "text-primary";
    case "MEDIUM_RISK":
      return "text-warning";
    case "HIGH_RISK":
    case "CRITICAL_RISK":
      return "text-danger";
  }
}

/** Stroke colour (hex) for the score gauge. */
export function scoreStroke(score: number): string {
  if (score >= 90) return "#22C55E";
  if (score >= 70) return "#84CC16";
  if (score >= 40) return "#F59E0B";
  if (score >= 25) return "#F97316";
  return "#EF4444";
}

interface SeverityStyle {
  label: string;
  text: string;
  bg: string;
  border: string;
  dot: string;
}

export const SEVERITY_STYLE: Record<Severity, SeverityStyle> = {
  CRITICAL: {
    label: "Critical",
    text: "text-danger",
    bg: "bg-danger/10",
    border: "border-danger/40",
    dot: "bg-danger",
  },
  HIGH: {
    label: "High",
    text: "text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/40",
    dot: "bg-orange-500",
  },
  MEDIUM: {
    label: "Medium",
    text: "text-warning",
    bg: "bg-warning/10",
    border: "border-warning/40",
    dot: "bg-warning",
  },
  LOW: {
    label: "Low",
    text: "text-info",
    bg: "bg-info/10",
    border: "border-info/40",
    dot: "bg-info",
  },
  INFO: {
    label: "Info",
    text: "text-muted",
    bg: "bg-muted/10",
    border: "border-line",
    dot: "bg-muted",
  },
};

export const CATEGORY_LABEL: Record<Category, string> = {
  STRUCTURE: "Structure",
  PLUGIN_YML: "plugin.yml",
  NETWORK: "Network",
  PROCESS: "Process",
  CLASS_LOADING: "Class loading",
  NATIVE: "Native code",
  FILESYSTEM: "Filesystem",
  CRYPTO: "Crypto",
  REFLECTION: "Reflection",
  SYSTEM: "JVM control",
  OBFUSCATION: "Obfuscation",
  STRING_IOC: "Indicators",
  PROVENANCE: "Provenance",
};

export const SEVERITY_ORDER: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
];

import type { Category, SandboxStatus, Severity, Verdict } from "./types";

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
  if (score >= 90) return "#A3E635";
  if (score >= 70) return "#84CC16";
  if (score >= 40) return "#FBBF24";
  if (score >= 25) return "#FB923C";
  return "#FB7185";
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
    border: "border-danger/30",
    dot: "bg-danger",
  },
  HIGH: {
    label: "High",
    text: "text-orange-400",
    bg: "bg-orange-400/10",
    border: "border-orange-400/30",
    dot: "bg-orange-400",
  },
  MEDIUM: {
    label: "Medium",
    text: "text-warning",
    bg: "bg-warning/10",
    border: "border-warning/30",
    dot: "bg-warning",
  },
  LOW: {
    label: "Low",
    text: "text-info",
    bg: "bg-info/10",
    border: "border-info/30",
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
  SCRIPTING: "Scripting",
  DESERIALIZATION: "Deserialization",
  SYSTEM: "JVM control",
  OBFUSCATION: "Obfuscation",
  STRING_IOC: "Indicators",
  SUPPLY_CHAIN: "Supply chain",
  COMBO: "Correlated",
  MINECRAFT: "Minecraft API",
  MALWARE_SIGNATURE: "Known malware",
  RESOURCE_PACK: "Resource pack",
  DATA_PACK: "Data pack",
  PERFORMANCE: "Performance",
  PROVENANCE: "Provenance",
};

export const SEVERITY_ORDER: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
];

export const SANDBOX_STATUS_LABEL: Record<SandboxStatus, string> = {
  DISABLED: "Disabled",
  PENDING: "Queued",
  RUNNING: "Running",
  COMPLETED: "Completed",
  SKIPPED: "Skipped",
  UNAVAILABLE: "Unavailable",
  FAILED: "Failed",
};

/** Human label for a dynamic behavior-event type (also used for dynamic findings). */
export function behaviorTypeLabel(type: string): string {
  const labels: Record<string, string> = {
    PROCESS_EXEC: "Process execution",
    DEFINE_CLASS: "Runtime class definition",
    LOAD_LIBRARY: "Native library load",
    JNDI_LOOKUP: "JNDI lookup",
    SECURITY_MANAGER: "Sandbox-escape attempt",
    DESERIALIZE: "Deserialization",
    NETWORK_CONNECT: "Outbound connection",
    NETWORK_LISTEN: "Listening socket",
    SCRIPTING: "Script evaluation",
    DNS_RESOLVE: "DNS resolution",
    FILE_WRITE: "Filesystem write",
    FILE_READ: "Filesystem read",
    REFLECTION: "Reflection",
    SET_PROPERTY: "System property change",
    ENV_READ: "Environment read",
    OUTPUT: "Output",
    LIFECYCLE: "Lifecycle",
    ERROR: "Harness error",
  };
  return labels[type] ?? type;
}

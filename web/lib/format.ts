import type { Severity, Verdict } from "./types";

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
  text: string;
  bg: string;
  border: string;
  dot: string;
}

/**
 * Per-severity colour tokens. The human-readable labels live in the i18n catalogue
 * (lib/i18n.tsx) so they can switch language; this map is purely visual.
 */
export const SEVERITY_STYLE: Record<Severity, SeverityStyle> = {
  CRITICAL: {
    text: "text-danger",
    bg: "bg-danger/10",
    border: "border-danger/30",
    dot: "bg-danger",
  },
  HIGH: {
    text: "text-orange-400",
    bg: "bg-orange-400/10",
    border: "border-orange-400/30",
    dot: "bg-orange-400",
  },
  MEDIUM: {
    text: "text-warning",
    bg: "bg-warning/10",
    border: "border-warning/30",
    dot: "bg-warning",
  },
  LOW: {
    text: "text-info",
    bg: "bg-info/10",
    border: "border-info/30",
    dot: "bg-info",
  },
  INFO: {
    text: "text-muted",
    bg: "bg-muted/10",
    border: "border-line",
    dot: "bg-muted",
  },
};

export const SEVERITY_ORDER: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
];

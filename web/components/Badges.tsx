import { SEVERITY_STYLE, VERDICT_LABEL, verdictColor } from "@/lib/format";
import type { Severity, Verdict } from "@/lib/types";

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const color = verdictColor(verdict);
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border border-current/30 px-3 py-1 text-sm font-medium ${color}`}
    >
      <span className="h-2 w-2 rounded-full bg-current" />
      {VERDICT_LABEL[verdict]}
    </span>
  );
}

export function SeverityPill({ severity }: { severity: Severity }) {
  const s = SEVERITY_STYLE[severity];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium ${s.text} ${s.bg} ${s.border}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  );
}

export function CountChip({
  label,
  value,
  className = "",
}: {
  label: string;
  value: number;
  className?: string;
}) {
  return (
    <div
      className={`rounded-lg border border-line bg-card/60 px-3 py-2 text-center ${className}`}
    >
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      <div className="text-xs uppercase tracking-wide text-muted">{label}</div>
    </div>
  );
}

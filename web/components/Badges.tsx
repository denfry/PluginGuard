import { SEVERITY_STYLE, VERDICT_LABEL, verdictColor } from "@/lib/format";
import type { Severity, Verdict } from "@/lib/types";

/** Verdict rendered as a forensic "stamp": monospace, uppercase, letterspaced. */
export function VerdictBadge({
  verdict,
  size = "md",
}: {
  verdict: Verdict;
  size?: "md" | "lg";
}) {
  const color = verdictColor(verdict);
  const sizing =
    size === "lg"
      ? "px-3.5 py-1.5 text-xs tracking-[0.16em]"
      : "px-2.5 py-1 text-[11px] tracking-[0.14em]";
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-md border border-current/40 bg-current/10 font-mono font-medium uppercase ${sizing} ${color}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {VERDICT_LABEL[verdict]}
    </span>
  );
}

export function SeverityPill({ severity }: { severity: Severity }) {
  const s = SEVERITY_STYLE[severity];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-[0.1em] ${s.text} ${s.bg} ${s.border}`}
    >
      <span className={`h-1 w-1 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  );
}

/** A single severity counter: dot + label above a large tabular number. */
export function SeverityStat({
  label,
  value,
  dotClass,
}: {
  label: string;
  value: number;
  dotClass: string;
}) {
  return (
    <div
      className={`flex flex-col items-center gap-1 ${value === 0 ? "opacity-35" : ""}`}
    >
      <span className="micro-label flex items-center gap-1.5 text-muted">
        <span className={`h-1.5 w-1.5 rounded-full ${dotClass}`} />
        {label}
      </span>
      <span className="font-display text-2xl font-semibold tabular-nums">
        {value}
      </span>
    </div>
  );
}

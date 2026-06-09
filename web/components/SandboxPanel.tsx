"use client";

import { useState } from "react";
import type { DynamicFinding, SandboxReport } from "@/lib/types";
import {
  SANDBOX_STATUS_LABEL,
  SEVERITY_STYLE,
  behaviorTypeLabel,
} from "@/lib/format";
import { Panel } from "./Panel";
import { SeverityPill } from "./Badges";
import { EyeIcon, ChevronIcon } from "./icons";

function StatusBadge({ report }: { report: SandboxReport }) {
  const { status } = report;
  const tone =
    status === "COMPLETED"
      ? report.worstSeverity && report.worstSeverity !== "INFO"
        ? "border-danger/40 bg-danger/10 text-danger"
        : "border-primary/40 bg-primary/10 text-primary"
      : status === "RUNNING" || status === "PENDING"
        ? "border-info/40 bg-info/10 text-info"
        : status === "FAILED"
          ? "border-warning/40 bg-warning/10 text-warning"
          : "border-line bg-bg text-muted";
  const running = status === "RUNNING" || status === "PENDING";
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-md border px-2.5 py-1 font-mono text-[11px] font-medium uppercase tracking-[0.12em] ${tone}`}
    >
      {running && (
        <span className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" />
      )}
      {SANDBOX_STATUS_LABEL[status]}
    </span>
  );
}

function Chip({
  tone,
  children,
}: {
  tone: "danger" | "primary" | "neutral";
  children: React.ReactNode;
}) {
  const classes = {
    danger: "border-danger/40 bg-danger/10 text-danger",
    primary: "border-primary/40 bg-primary/10 text-primary",
    neutral: "border-line bg-bg text-muted",
  }[tone];
  return (
    <span
      className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-[0.08em] ${classes}`}
    >
      {children}
    </span>
  );
}

function DynamicFindingRow({ finding }: { finding: DynamicFinding }) {
  const style = SEVERITY_STYLE[finding.severity];
  return (
    <div className="overflow-hidden rounded-lg border border-line bg-bg/60">
      <div className="flex gap-3 px-4 py-3.5">
        <span
          className={`w-0.5 shrink-0 self-stretch rounded-full ${style.dot}`}
        />
        <div className="min-w-0 flex-1 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityPill severity={finding.severity} />
            <span className="micro-label text-faint">
              {behaviorTypeLabel(finding.eventType)}
            </span>
            {finding.correlation === "DYNAMIC_ONLY" ? (
              <Chip tone="danger">New — static missed it</Chip>
            ) : (
              <Chip tone="neutral">Confirms static</Chip>
            )}
            {finding.blocked && <Chip tone="primary">Blocked</Chip>}
            {finding.occurrences > 1 && (
              <span className="font-mono text-[11px] text-faint">
                ×{finding.occurrences}
              </span>
            )}
          </div>
          <p className="font-medium text-ink">{finding.title}</p>
          {finding.target && (
            <code className="block max-w-full truncate rounded border border-line bg-bg px-2 py-1 font-mono text-xs text-muted">
              {finding.target}
            </code>
          )}
          <p className="text-sm leading-relaxed text-ink/80">
            {finding.description}
          </p>
          {finding.recommendation && (
            <div className="border-l-2 border-primary/60 pl-3 text-sm leading-relaxed text-ink/85">
              <span className="font-medium text-primary">
                Recommendation —{" "}
              </span>
              {finding.recommendation}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function BehaviorTrail({ report }: { report: SandboxReport }) {
  const [open, setOpen] = useState(false);
  if (report.behaviorEvents.length === 0) return null;
  return (
    <div className="overflow-hidden rounded-lg border border-line bg-bg/40">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center justify-between px-4 py-2.5 text-left transition-colors hover:bg-card"
      >
        <span className="micro-label text-muted">
          Behavior trail — {report.behaviorEventCount} event
          {report.behaviorEventCount === 1 ? "" : "s"}
        </span>
        <ChevronIcon
          className={`h-4 w-4 text-faint transition-transform duration-200 ${open ? "rotate-180" : ""}`}
        />
      </button>
      {open && (
        <ul className="max-h-72 divide-y divide-line overflow-auto border-t border-line">
          {report.behaviorEvents.map((e, i) => (
            <li key={i} className="flex items-center gap-3 px-4 py-2 text-xs">
              <span className="w-40 shrink-0 font-mono text-muted">
                {behaviorTypeLabel(e.type)}
              </span>
              <code className="flex-1 truncate font-mono text-ink/70">
                {e.target ?? e.detail ?? ""}
              </code>
              {e.blocked && (
                <span className="micro-label shrink-0 text-primary">
                  blocked
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function SandboxPanel({ report }: { report: SandboxReport }) {
  // The sandbox feature being off is not interesting to surface prominently.
  if (report.status === "DISABLED") return null;

  const findings = report.dynamicFindings;
  const inactive =
    report.status === "SKIPPED" ||
    report.status === "UNAVAILABLE" ||
    report.status === "FAILED";

  return (
    <Panel
      title="dynamic sandbox"
      icon={<EyeIcon className="h-4 w-4" />}
      action={<StatusBadge report={report} />}
    >
      <div className="space-y-4">
        <p className="text-xs leading-relaxed text-muted">
          The plugin was executed in an isolated, network-blocked container and
          its real behavior recorded. This catches reflection-built or decoded
          actions that static analysis cannot see.
        </p>

        {(report.status === "RUNNING" || report.status === "PENDING") && (
          <p className="text-sm text-info">
            {report.note ?? "Running the plugin in the sandbox…"} This page
            refreshes automatically.
          </p>
        )}

        {inactive && (
          <p className="text-sm text-muted">
            {report.note ?? "No dynamic analysis was performed."}
          </p>
        )}

        {report.status === "COMPLETED" && findings.length === 0 && (
          <p className="text-sm text-muted">
            No dangerous runtime behavior was observed in the code paths that
            were triggered.
          </p>
        )}

        {findings.length > 0 && (
          <div className="space-y-2">
            {findings.map((f, i) => (
              <DynamicFindingRow key={`${f.ruleId}-${i}`} finding={f} />
            ))}
          </div>
        )}

        {report.status === "COMPLETED" && <BehaviorTrail report={report} />}

        {report.caveats.length > 0 && (
          <details className="text-xs text-muted">
            <summary className="micro-label cursor-pointer select-none text-faint transition-colors hover:text-muted">
              What a sandbox can and cannot prove
            </summary>
            <ul className="mt-2 list-disc space-y-1.5 pl-4 leading-relaxed">
              {report.caveats.map((c, i) => (
                <li key={i}>{c}</li>
              ))}
            </ul>
          </details>
        )}
      </div>
    </Panel>
  );
}

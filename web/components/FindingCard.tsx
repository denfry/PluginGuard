"use client";

import { useState } from "react";
import type { Finding } from "@/lib/types";
import { CATEGORY_LABEL, SEVERITY_STYLE } from "@/lib/format";
import { SeverityPill } from "./Badges";
import { ChevronIcon } from "./icons";

export function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const style = SEVERITY_STYLE[finding.severity];

  return (
    <div
      className={`rounded-xl border ${style.border} bg-card/60 overflow-hidden`}
    >
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-card transition"
      >
        <span className={`h-8 w-1 rounded-full ${style.dot} shrink-0`} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityPill severity={finding.severity} />
            <span className="text-xs text-muted">
              {CATEGORY_LABEL[finding.category]}
            </span>
          </div>
          <p className="mt-1 font-medium text-ink truncate">{finding.title}</p>
        </div>
        {finding.evidence && (
          <code className="hidden md:block max-w-[16rem] truncate rounded bg-bg/70 px-2 py-1 text-xs text-muted font-mono">
            {finding.evidence}
          </code>
        )}
        <ChevronIcon
          className={`h-5 w-5 shrink-0 text-muted transition-transform ${
            open ? "rotate-180" : ""
          }`}
        />
      </button>

      {open && (
        <div className="border-t border-line/60 px-4 py-4 space-y-3 text-sm">
          <p className="text-ink/90 leading-relaxed">{finding.description}</p>
          {finding.location && (
            <div>
              <span className="text-muted">Location: </span>
              <code className="font-mono text-info break-all">
                {finding.location}
              </code>
            </div>
          )}
          {finding.evidence && (
            <div className="md:hidden">
              <span className="text-muted">Evidence: </span>
              <code className="font-mono text-muted break-all">
                {finding.evidence}
              </code>
            </div>
          )}
          {finding.recommendation && (
            <div className="rounded-lg border border-line/60 bg-bg/40 px-3 py-2">
              <span className="text-primary font-medium">Recommendation. </span>
              <span className="text-ink/80">{finding.recommendation}</span>
            </div>
          )}
          <div className="flex items-center gap-3 text-xs text-muted pt-1">
            <span className="font-mono">{finding.ruleId}</span>
            {finding.scoreImpact > 0 && (
              <span>· −{finding.scoreImpact} to score</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

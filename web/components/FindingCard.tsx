"use client";

import type { ReactNode } from "react";
import type { Finding } from "@/lib/types";
import { SEVERITY_STYLE } from "@/lib/format";
import { useI18n } from "@/lib/i18n";
import { localizeFinding } from "@/lib/findings-i18n";
import { SeverityPill } from "./Badges";
import { ChevronIcon } from "./icons";

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-3">
      <dt className="micro-label w-24 shrink-0 pt-0.5 text-faint">{label}</dt>
      <dd className="min-w-0 break-all font-mono text-xs leading-relaxed">
        {children}
      </dd>
    </div>
  );
}

export function FindingCard({
  finding,
  open,
  onToggle,
}: {
  finding: Finding;
  open: boolean;
  onToggle: () => void;
}) {
  const { t, lang } = useI18n();
  const style = SEVERITY_STYLE[finding.severity];
  const text = localizeFinding(finding, lang);

  return (
    <div
      className={`overflow-hidden rounded-lg border bg-card transition-colors duration-200 ${
        open ? "border-line-strong" : "border-line hover:border-line-strong"
      }`}
    >
      <button
        onClick={onToggle}
        aria-expanded={open}
        className="flex w-full items-center gap-3 px-4 py-3 text-left"
      >
        <span
          className={`w-0.5 shrink-0 self-stretch rounded-full ${style.dot}`}
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityPill severity={finding.severity} />
            <span className="micro-label text-faint">
              {t(`category.${finding.category}`)}
            </span>
            {finding.nestedPath && (
              <span className="truncate font-mono text-[11px] text-faint">
                {t("finding.in")} {finding.nestedPath}
              </span>
            )}
          </div>
          <p className="mt-1.5 font-medium text-ink">{text.title}</p>
        </div>
        {finding.evidence && !open && (
          <code className="hidden max-w-[14rem] truncate rounded border border-line bg-bg px-2 py-1 font-mono text-[11px] text-muted lg:block">
            {finding.evidence}
          </code>
        )}
        <ChevronIcon
          className={`h-4 w-4 shrink-0 text-faint transition-transform duration-200 ${
            open ? "rotate-180" : ""
          }`}
        />
      </button>

      <div
        className={`grid transition-[grid-template-rows] duration-200 ease-out ${
          open ? "grid-rows-[1fr]" : "grid-rows-[0fr]"
        }`}
      >
        <div className="overflow-hidden">
          <div className="space-y-3.5 border-t border-line px-4 py-4 pl-[1.875rem]">
            <p className="text-sm leading-relaxed text-ink/90">
              {text.description}
            </p>

            <dl className="space-y-2">
              {finding.location && (
                <DetailRow label={t("finding.location")}>
                  <span className="text-info">{finding.location}</span>
                </DetailRow>
              )}
              {finding.evidence && (
                <DetailRow label={t("finding.evidence")}>
                  <span className="text-muted">{finding.evidence}</span>
                </DetailRow>
              )}
              {finding.relatedRuleIds && finding.relatedRuleIds.length > 0 && (
                <DetailRow label={t("finding.correlated")}>
                  <span className="text-warning">
                    {finding.relatedRuleIds.join(", ")}
                  </span>
                </DetailRow>
              )}
            </dl>

            {text.recommendation && (
              <div className="border-l-2 border-primary/60 pl-3 text-sm leading-relaxed text-ink/85">
                <span className="font-medium text-primary">
                  {t("finding.recommendation")}{" "}
                </span>
                {text.recommendation}
              </div>
            )}

            <div className="flex items-center gap-3 pt-0.5 font-mono text-[11px] text-faint">
              <span>{finding.ruleId}</span>
              {finding.scoreImpact > 0 && (
                <span>{t("finding.pts", { n: finding.scoreImpact })}</span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

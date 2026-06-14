"use client";

import type { ClassDiff, ProvenanceReport } from "@/lib/types";
import { useI18n } from "@/lib/i18n";
import { Panel } from "./Panel";
import { FingerprintIcon, CheckIcon, AlertIcon } from "./icons";

function StatusBadge({ report }: { report: ProvenanceReport }) {
  const { t } = useI18n();
  const { status } = report;
  const tone =
    status === "VERIFIED"
      ? "border-primary/40 bg-primary/10 text-primary"
      : status === "TAMPERED"
        ? "border-danger/40 bg-danger/10 text-danger"
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
      {t(`provenanceStatus.${status}`)}
    </span>
  );
}

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <dt className="micro-label text-faint">{label}</dt>
      <dd className="break-all text-sm text-ink">{children}</dd>
    </div>
  );
}

function MatchDetails({ report }: { report: ProvenanceReport }) {
  const { t } = useI18n();
  const m = report.match;
  if (!m) return null;
  return (
    <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
      <DetailRow label={t("provenance.project")}>
        {m.projectUrl ? (
          <a
            href={m.projectUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary underline-offset-2 hover:underline"
          >
            {m.projectName ?? m.projectUrl}
          </a>
        ) : (
          (m.projectName ?? "—")
        )}
      </DetailRow>
      <DetailRow label={t("provenance.version")}>{m.matchedVersion ?? "—"}</DetailRow>
      <DetailRow label={t("provenance.source")}>{m.source}</DetailRow>
      {m.officialFileName && (
        <DetailRow label={t("provenance.officialFile")}>
          <code className="font-mono text-xs">{m.officialFileName}</code>
        </DetailRow>
      )}
    </dl>
  );
}

function ClassList({
  title,
  classes,
  tone,
}: {
  title: string;
  classes: string[];
  tone: "danger" | "warning" | "muted";
}) {
  if (classes.length === 0) return null;
  const dot = {
    danger: "bg-danger",
    warning: "bg-warning",
    muted: "bg-line",
  }[tone];
  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-2">
        <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
        <span className="micro-label text-muted">{title}</span>
      </div>
      <ul className="space-y-1 pl-3.5">
        {classes.map((c) => (
          <li
            key={c}
            className="break-all font-mono text-xs text-ink/80"
          >
            {c}
          </li>
        ))}
      </ul>
    </div>
  );
}

function DiffView({ diff }: { diff: ClassDiff }) {
  const { t } = useI18n();
  return (
    <div className="space-y-3 rounded-lg border border-line bg-bg/40 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="micro-label text-faint">{t("provenance.diffTitle")}</span>
        <span className="font-mono text-[11px] text-faint">
          {t("provenance.diffCounts", {
            o: diff.officialClassCount,
            u: diff.uploadedClassCount,
          })}
        </span>
      </div>
      <ClassList
        title={t("provenance.diffAdded", { n: diff.addedClasses.length })}
        classes={diff.addedClasses}
        tone="danger"
      />
      <ClassList
        title={t("provenance.diffModified", { n: diff.modifiedClasses.length })}
        classes={diff.modifiedClasses}
        tone="warning"
      />
      <ClassList
        title={t("provenance.diffRemoved", { n: diff.removedClasses.length })}
        classes={diff.removedClasses}
        tone="muted"
      />
      {diff.truncated && (
        <p className="text-xs text-faint">{t("provenance.diffTruncated")}</p>
      )}
    </div>
  );
}

export function ProvenancePanel({ report }: { report: ProvenanceReport }) {
  const { t } = useI18n();
  // The feature being off is not interesting to surface.
  if (report.status === "DISABLED") return null;

  const { status } = report;
  const name = report.match?.projectName ?? report.pluginName ?? "—";
  const version = report.match?.matchedVersion ?? report.pluginVersion ?? "";
  const source = report.match?.source ?? report.sourcesQueried.join(", ");

  return (
    <Panel
      title={t("provenance.title")}
      icon={<FingerprintIcon className="h-4 w-4" />}
      action={<StatusBadge report={report} />}
    >
      <div className="space-y-4">
        <p className="text-xs leading-relaxed text-muted">{t("provenance.intro")}</p>

        {(status === "RUNNING" || status === "PENDING") && (
          <p className="text-sm text-info">
            {t("provenance.running")} {t("provenance.runningSuffix")}
          </p>
        )}

        {status === "VERIFIED" && (
          <div className="space-y-3 rounded-lg border border-primary/40 bg-primary/5 p-4">
            <div className="flex items-center gap-2">
              <CheckIcon className="h-4 w-4 text-primary" />
              <span className="font-medium text-primary">
                {t("provenance.verifiedTitle")}
              </span>
            </div>
            <p className="text-sm leading-relaxed text-ink/85">
              {t("provenance.verifiedBody")}
            </p>
            <MatchDetails report={report} />
          </div>
        )}

        {status === "TAMPERED" && (
          <div className="space-y-3 rounded-lg border border-danger/40 bg-danger/5 p-4">
            <div className="flex items-center gap-2">
              <AlertIcon className="h-4 w-4 text-danger" />
              <span className="font-medium text-danger">
                {t("provenance.tamperedTitle")}
              </span>
            </div>
            <p className="text-sm leading-relaxed text-ink/85">
              {t("provenance.tamperedBody", { name, version, source })}
            </p>
            <MatchDetails report={report} />
            {report.diff && <DiffView diff={report.diff} />}
          </div>
        )}

        {status === "NOT_FOUND" && (
          <div className="space-y-2 rounded-lg border border-line bg-bg/60 p-4">
            <p className="font-medium text-ink">{t("provenance.notFoundTitle")}</p>
            <p className="text-sm leading-relaxed text-muted">
              {t("provenance.notFoundBody", { name })}
            </p>
          </div>
        )}

        {status === "UNVERIFIED" && (
          <p className="text-sm text-muted">{t("provenance.unverifiedBody")}</p>
        )}

        {(status === "SKIPPED" || status === "FAILED") && (
          <p className="text-sm text-muted">{report.note}</p>
        )}

        {report.sourcesQueried.length > 0 && status !== "VERIFIED" && (
          <p className="micro-label text-faint">
            {t("provenance.sources")}: {report.sourcesQueried.join(" · ")}
          </p>
        )}

        {report.caveats.length > 0 && (
          <details className="text-xs text-muted">
            <summary className="micro-label cursor-pointer select-none text-faint transition-colors hover:text-muted">
              {t("provenance.caveatsSummary")}
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

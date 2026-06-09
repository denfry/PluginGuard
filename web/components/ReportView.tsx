import type { ScanResult } from "@/lib/types";
import { formatBytes, SEVERITY_ORDER } from "@/lib/format";
import { ScoreGauge } from "./ScoreGauge";
import { VerdictBadge, CountChip } from "./Badges";
import { Panel } from "./Panel";
import { FindingCard } from "./FindingCard";
import {
  AlertIcon,
  BoxIcon,
  EyeIcon,
  FileIcon,
  FolderIcon,
  NetworkIcon,
} from "./icons";
import type { ReactNode } from "react";

function MetaRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs uppercase tracking-wide text-muted">{label}</dt>
      <dd className="text-sm text-ink break-all">{value}</dd>
    </div>
  );
}

function TagList({ items, empty }: { items: string[]; empty: string }) {
  if (!items.length) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((item) => (
        <span
          key={item}
          className="rounded-md border border-line bg-bg/50 px-2 py-0.5 text-xs font-mono text-ink/80"
        >
          {item}
        </span>
      ))}
    </div>
  );
}

function List({ items, empty }: { items: string[]; empty: string }) {
  if (!items.length) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <ul className="space-y-1.5">
      {items.map((item) => (
        <li key={item} className="font-mono text-sm text-ink/80 break-all">
          {item}
        </li>
      ))}
    </ul>
  );
}

export function ReportView({ report }: { report: ScanResult }) {
  const { counts, pluginInfo, summaries } = report;

  const orderedFindings = report.findings;
  const grouped = SEVERITY_ORDER.map((sev) => ({
    sev,
    items: orderedFindings.filter((f) => f.severity === sev),
  })).filter((g) => g.items.length > 0);

  return (
    <div className="container-page py-10 space-y-6">
      {/* Header */}
      <Panel className="overflow-hidden">
        <div className="flex flex-col lg:flex-row gap-8 lg:items-center">
          <div className="flex-1 space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-semibold break-all">
                {report.fileName}
              </h1>
              <VerdictBadge verdict={report.verdict} />
            </div>
            <dl className="grid grid-cols-2 sm:grid-cols-3 gap-4">
              <MetaRow label="Platform" value={report.platform} />
              <MetaRow label="Size" value={formatBytes(report.sizeBytes)} />
              <MetaRow
                label="MC API"
                value={report.mcApiVersion ?? "—"}
              />
              <MetaRow
                label="Main class"
                value={
                  <span className="font-mono">{report.mainClass ?? "—"}</span>
                }
              />
              <MetaRow
                label="Classes / methods"
                value={`${summaries.classCount} / ${summaries.methodCount}`}
              />
              <MetaRow
                label="Obfuscation"
                value={`${report.obfuscationScore}/100`}
              />
            </dl>
            <MetaRow
              label="SHA-256"
              value={<span className="font-mono text-xs">{report.sha256}</span>}
            />
          </div>

          <div className="flex flex-col items-center gap-4 shrink-0">
            <ScoreGauge score={report.score} />
            <div className="grid grid-cols-4 gap-2 w-full max-w-xs">
              <CountChip label="Crit" value={counts.critical} />
              <CountChip label="High" value={counts.high} />
              <CountChip label="Med" value={counts.medium} />
              <CountChip label="Low" value={counts.low} />
            </div>
          </div>
        </div>
      </Panel>

      {/* Metadata + summaries */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Panel title="plugin.yml" icon={<FileIcon className="h-4 w-4" />}>
          {pluginInfo ? (
            <div className="space-y-4">
              <dl className="grid grid-cols-2 gap-3">
                <MetaRow label="Name" value={pluginInfo.name ?? "—"} />
                <MetaRow label="Version" value={pluginInfo.version ?? "—"} />
              </dl>
              <div className="space-y-1.5">
                <p className="text-xs uppercase tracking-wide text-muted">
                  Authors
                </p>
                <TagList items={pluginInfo.authors} empty="None declared" />
              </div>
              <div className="space-y-1.5">
                <p className="text-xs uppercase tracking-wide text-muted">
                  Commands
                </p>
                <TagList items={pluginInfo.commands} empty="None" />
              </div>
              <div className="space-y-1.5">
                <p className="text-xs uppercase tracking-wide text-muted">
                  Permissions
                </p>
                <TagList items={pluginInfo.permissions} empty="None" />
              </div>
              <div className="space-y-1.5">
                <p className="text-xs uppercase tracking-wide text-muted">
                  Dependencies
                </p>
                <TagList
                  items={[...pluginInfo.depend, ...pluginInfo.softDepend]}
                  empty="None"
                />
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted">No plugin descriptor found.</p>
          )}
        </Panel>

        <Panel title="Network" icon={<NetworkIcon className="h-4 w-4" />}>
          <List items={summaries.network} empty="No network indicators found." />
        </Panel>

        <Panel title="Filesystem" icon={<FolderIcon className="h-4 w-4" />}>
          <List
            items={summaries.filesystem}
            empty="No notable filesystem paths."
          />
        </Panel>

        <Panel
          title="Dependencies"
          icon={<BoxIcon className="h-4 w-4" />}
          className="lg:col-span-2"
        >
          {summaries.dependencies.length ? (
            <div className="flex flex-wrap gap-1.5">
              {summaries.dependencies.map((d) => (
                <span
                  key={`${d.name}@${d.version}`}
                  className="rounded-md border border-line bg-bg/50 px-2 py-0.5 text-xs font-mono text-ink/80"
                >
                  {d.name}
                  {d.version ? `@${d.version}` : ""}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted">No bundled dependencies detected.</p>
          )}
        </Panel>

        <Panel title="Obfuscation" icon={<EyeIcon className="h-4 w-4" />}>
          <div className="flex items-end gap-3">
            <span className="text-3xl font-semibold tabular-nums">
              {report.obfuscationScore}
            </span>
            <span className="text-muted text-sm mb-1">/ 100</span>
          </div>
          <div className="mt-3 h-2 w-full rounded-full bg-line/60 overflow-hidden">
            <div
              className="h-full rounded-full bg-info"
              style={{ width: `${report.obfuscationScore}%` }}
            />
          </div>
          <p className="mt-2 text-xs text-muted">
            Higher means more obfuscated. Not malicious on its own.
          </p>
        </Panel>
      </div>

      {/* Findings */}
      <Panel
        title={`Findings (${orderedFindings.length})`}
        icon={<AlertIcon className="h-4 w-4" />}
      >
        {orderedFindings.length === 0 ? (
          <p className="text-sm text-muted">No findings.</p>
        ) : (
          <div className="space-y-6">
            {grouped.map((group) => (
              <div key={group.sev} className="space-y-2">
                <div className="space-y-2">
                  {group.items.map((f, i) => (
                    <FindingCard key={`${f.ruleId}-${i}`} finding={f} />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {report.notes.length > 0 && (
        <Panel title="Engine notes">
          <ul className="space-y-1 text-sm text-muted">
            {report.notes.map((n, i) => (
              <li key={i}>· {n}</li>
            ))}
          </ul>
        </Panel>
      )}

      <p className="text-center text-xs text-muted">
        Analyzed in {report.durationMs} ms · engine v{report.engineVersion} ·
        static analysis, the plugin was never executed.
      </p>
    </div>
  );
}

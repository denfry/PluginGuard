"use client";

import { useMemo, useState, type ReactNode } from "react";
import type { ScanResult, Severity } from "@/lib/types";
import { formatBytes, SEVERITY_ORDER, SEVERITY_STYLE } from "@/lib/format";
import { ScoreGauge } from "./ScoreGauge";
import { VerdictBadge, SeverityStat } from "./Badges";
import { Panel } from "./Panel";
import { FindingCard } from "./FindingCard";
import { SandboxPanel } from "./SandboxPanel";
import {
  AlertIcon,
  BoxIcon,
  CheckIcon,
  CopyIcon,
  EyeIcon,
  FileIcon,
  FolderIcon,
  NetworkIcon,
} from "./icons";

function MetaRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <dt className="micro-label text-faint">{label}</dt>
      <dd className="break-all text-sm text-ink">{value}</dd>
    </div>
  );
}

function TagList({ items, empty }: { items: string[]; empty: string }) {
  if (!items.length) return <p className="text-sm text-faint">{empty}</p>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((item) => (
        <span
          key={item}
          className="rounded border border-line bg-bg px-2 py-0.5 font-mono text-xs text-ink/80"
        >
          {item}
        </span>
      ))}
    </div>
  );
}

function HairlineList({ items, empty }: { items: string[]; empty: string }) {
  if (!items.length) return <p className="text-sm text-faint">{empty}</p>;
  return (
    <ul className="divide-y divide-line">
      {items.map((item) => (
        <li
          key={item}
          className="break-all py-1.5 font-mono text-sm text-ink/80 first:pt-0 last:pb-0"
        >
          {item}
        </li>
      ))}
    </ul>
  );
}

function CopyHashButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard
          .writeText(value)
          .then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          })
          .catch(() => {});
      }}
      aria-label="Copy SHA-256"
      className={`shrink-0 rounded-md border border-line p-1.5 transition-colors ${
        copied ? "text-primary" : "text-faint hover:border-line-strong hover:text-ink"
      }`}
    >
      {copied ? (
        <CheckIcon className="h-3.5 w-3.5" />
      ) : (
        <CopyIcon className="h-3.5 w-3.5" />
      )}
    </button>
  );
}

/** 24-segment instrument bar for the obfuscation score. */
function SegmentBar({ value }: { value: number }) {
  const segments = 24;
  const filled = Math.round((Math.max(0, Math.min(100, value)) / 100) * segments);
  return (
    <div className="flex gap-[3px]">
      {Array.from({ length: segments }, (_, i) => (
        <span
          key={i}
          className={`h-3 flex-1 rounded-[1px] ${i < filled ? "bg-info" : "bg-line"}`}
        />
      ))}
    </div>
  );
}

/** Compact labels so the five-stat row fits a phone screen. */
const SHORT_LABEL: Record<Severity, string> = {
  CRITICAL: "Crit",
  HIGH: "High",
  MEDIUM: "Med",
  LOW: "Low",
  INFO: "Info",
};

const FILTERS: { key: Severity; countKey: keyof ScanResult["counts"] }[] = [
  { key: "CRITICAL", countKey: "critical" },
  { key: "HIGH", countKey: "high" },
  { key: "MEDIUM", countKey: "medium" },
  { key: "LOW", countKey: "low" },
  { key: "INFO", countKey: "info" },
];

export function ReportView({ report }: { report: ScanResult }) {
  const { counts, pluginInfo, summaries } = report;
  const findings = report.findings;

  const [filter, setFilter] = useState<Severity | "ALL">("ALL");
  // Critical findings start expanded — they are why the user is here.
  const [openSet, setOpenSet] = useState<ReadonlySet<number>>(
    () =>
      new Set(
        findings.flatMap((f, i) => (f.severity === "CRITICAL" ? [i] : [])),
      ),
  );

  const groups = useMemo(
    () =>
      SEVERITY_ORDER.map((sev) => ({
        sev,
        items: findings
          .map((f, i) => ({ finding: f, index: i }))
          .filter(({ finding }) => finding.severity === sev),
      })).filter((g) => g.items.length > 0),
    [findings],
  );
  const visibleGroups =
    filter === "ALL" ? groups : groups.filter((g) => g.sev === filter);

  function toggle(index: number) {
    setOpenSet((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }

  function setAll(open: boolean) {
    setOpenSet(
      open
        ? new Set(visibleGroups.flatMap((g) => g.items.map((it) => it.index)))
        : new Set(),
    );
  }

  return (
    <div className="container-page space-y-6 py-10">
      {/* Dossier header */}
      <Panel delay={0}>
        <div className="flex flex-col gap-10 lg:flex-row lg:items-center">
          <div className="min-w-0 flex-1 space-y-5">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="break-all font-display text-2xl font-semibold tracking-tight lg:text-3xl">
                {report.fileName}
              </h1>
              <VerdictBadge verdict={report.verdict} size="lg" />
            </div>

            <div className="flex min-w-0 items-center gap-2.5">
              <span className="micro-label shrink-0 text-faint">sha-256</span>
              <code className="truncate font-mono text-xs text-muted">
                {report.sha256}
              </code>
              <CopyHashButton value={report.sha256} />
            </div>

            <dl className="grid grid-cols-2 gap-x-8 gap-y-4 sm:grid-cols-3">
              <MetaRow label="platform" value={report.platform} />
              <MetaRow label="size" value={formatBytes(report.sizeBytes)} />
              <MetaRow label="mc api" value={report.mcApiVersion ?? "—"} />
              <MetaRow
                label="main class"
                value={
                  <span className="font-mono text-xs">
                    {report.mainClass ?? "—"}
                  </span>
                }
              />
              <MetaRow
                label="classes / methods"
                value={
                  <span className="tabular-nums">
                    {summaries.classCount} / {summaries.methodCount}
                  </span>
                }
              />
              <MetaRow
                label="analyzed in"
                value={<span className="tabular-nums">{report.durationMs} ms</span>}
              />
            </dl>
          </div>

          <div className="flex shrink-0 flex-col items-center gap-5">
            <ScoreGauge score={report.score} />
            <div className="flex flex-wrap items-start justify-center gap-x-6 gap-y-3">
              {FILTERS.map(({ key, countKey }) => (
                <SeverityStat
                  key={key}
                  label={SHORT_LABEL[key]}
                  value={counts[countKey]}
                  dotClass={SEVERITY_STYLE[key].dot}
                />
              ))}
            </div>
          </div>
        </div>
      </Panel>

      {/* Metadata + summaries */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Panel
          title={pluginInfo?.descriptorFile ?? "descriptor"}
          icon={<FileIcon className="h-4 w-4" />}
          delay={0.05}
        >
          {pluginInfo ? (
            <div className="space-y-4">
              <dl className="grid grid-cols-2 gap-3">
                <MetaRow label="name" value={pluginInfo.name ?? "—"} />
                <MetaRow label="version" value={pluginInfo.version ?? "—"} />
              </dl>
              <div className="space-y-1.5">
                <p className="micro-label text-faint">authors</p>
                <TagList items={pluginInfo.authors} empty="None declared" />
              </div>
              {report.artifactType.startsWith("PLUGIN") && (
                <>
                  <div className="space-y-1.5">
                    <p className="micro-label text-faint">commands</p>
                    <TagList items={pluginInfo.commands} empty="None" />
                  </div>
                  <div className="space-y-1.5">
                    <p className="micro-label text-faint">permissions</p>
                    <TagList items={pluginInfo.permissions} empty="None" />
                  </div>
                </>
              )}
              <div className="space-y-1.5">
                <p className="micro-label text-faint">dependencies</p>
                <TagList
                  items={[...pluginInfo.depend, ...pluginInfo.softDepend]}
                  empty="None"
                />
              </div>
            </div>
          ) : (
            <p className="text-sm text-faint">No descriptor found.</p>
          )}
        </Panel>

        <Panel
          title="network"
          icon={<NetworkIcon className="h-4 w-4" />}
          delay={0.1}
        >
          <HairlineList
            items={summaries.network}
            empty="No network indicators found."
          />
        </Panel>

        <Panel
          title="filesystem"
          icon={<FolderIcon className="h-4 w-4" />}
          delay={0.15}
        >
          <HairlineList
            items={summaries.filesystem}
            empty="No notable filesystem paths."
          />
        </Panel>

        <Panel
          title="dependencies"
          icon={<BoxIcon className="h-4 w-4" />}
          className="lg:col-span-2"
          delay={0.2}
        >
          {summaries.dependencies.length ? (
            <div className="flex flex-wrap gap-1.5">
              {summaries.dependencies.map((d) => (
                <span
                  key={`${d.name}@${d.version}`}
                  className="rounded border border-line bg-bg px-2 py-0.5 font-mono text-xs text-ink/80"
                >
                  {d.name}
                  {d.version ? `@${d.version}` : ""}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-sm text-faint">
              No bundled dependencies detected.
            </p>
          )}
        </Panel>

        <Panel
          title="obfuscation"
          icon={<EyeIcon className="h-4 w-4" />}
          delay={0.25}
        >
          <div className="flex items-end gap-2">
            <span className="font-display text-3xl font-semibold tabular-nums">
              {report.obfuscationScore}
            </span>
            <span className="mb-1 text-sm text-faint">/ 100</span>
          </div>
          <div className="mt-3">
            <SegmentBar value={report.obfuscationScore} />
          </div>
          <p className="mt-2.5 text-xs text-muted">
            Higher means more obfuscated. Not malicious on its own.
          </p>
        </Panel>
      </div>

      {/* Findings */}
      <Panel
        title={`findings — ${findings.length}`}
        icon={<AlertIcon className="h-4 w-4" />}
        delay={0.1}
        action={
          findings.length > 0 ? (
            <div className="micro-label flex items-center gap-2 text-faint">
              <button
                onClick={() => setAll(true)}
                className="transition-colors hover:text-ink"
              >
                Expand all
              </button>
              <span aria-hidden>/</span>
              <button
                onClick={() => setAll(false)}
                className="transition-colors hover:text-ink"
              >
                Collapse all
              </button>
            </div>
          ) : undefined
        }
      >
        {findings.length === 0 ? (
          <p className="text-sm text-faint">No findings.</p>
        ) : (
          <div className="space-y-5">
            {/* Severity filter */}
            <div className="flex flex-wrap items-center gap-1.5">
              <button
                onClick={() => setFilter("ALL")}
                className={`rounded-md border px-2.5 py-1 font-mono text-[11px] font-medium uppercase tracking-[0.1em] transition-colors ${
                  filter === "ALL"
                    ? "border-line-strong bg-raised text-ink"
                    : "border-line text-muted hover:text-ink"
                }`}
              >
                All <span className="tabular-nums">{findings.length}</span>
              </button>
              {FILTERS.filter(({ countKey }) => counts[countKey] > 0).map(
                ({ key, countKey }) => {
                  const s = SEVERITY_STYLE[key];
                  const active = filter === key;
                  return (
                    <button
                      key={key}
                      onClick={() => setFilter(active ? "ALL" : key)}
                      className={`rounded-md border px-2.5 py-1 font-mono text-[11px] font-medium uppercase tracking-[0.1em] transition-colors ${
                        active
                          ? `${s.text} ${s.bg} ${s.border}`
                          : "border-line text-muted hover:text-ink"
                      }`}
                    >
                      {s.label}{" "}
                      <span className="tabular-nums">{counts[countKey]}</span>
                    </button>
                  );
                },
              )}
            </div>

            {visibleGroups.map((group) => {
              const s = SEVERITY_STYLE[group.sev];
              return (
                <div key={group.sev} className="space-y-2">
                  <div className="flex items-center gap-3">
                    <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
                    <span className={`micro-label ${s.text}`}>
                      {s.label} — {group.items.length}
                    </span>
                    <span className="h-px flex-1 bg-line" />
                  </div>
                  {group.items.map(({ finding, index }) => (
                    <FindingCard
                      key={`${finding.ruleId}-${index}`}
                      finding={finding}
                      open={openSet.has(index)}
                      onToggle={() => toggle(index)}
                    />
                  ))}
                </div>
              );
            })}
          </div>
        )}
      </Panel>

      {report.sandbox && <SandboxPanel report={report.sandbox} />}

      {report.notes.length > 0 && (
        <Panel title="engine notes" delay={0.05}>
          <ul className="space-y-1.5 text-sm text-muted">
            {report.notes.map((n, i) => (
              <li key={i} className="flex gap-2">
                <span className="text-faint" aria-hidden>
                  ·
                </span>
                {n}
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <p className="micro-label text-center leading-5 text-faint">
        analyzed in {report.durationMs} ms · engine v{report.engineVersion} ·{" "}
        {report.sandbox &&
        ["RUNNING", "COMPLETED", "FAILED"].includes(report.sandbox.status)
          ? "static analysis + isolated sandbox run"
          : "static analysis — the plugin was never executed"}
      </p>
    </div>
  );
}

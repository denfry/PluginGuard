"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import type { ScanResult } from "@/lib/types";
import { ApiError, getDemo, getReport } from "@/lib/api";
import { ReportView } from "./ReportView";
import { AlertIcon } from "./icons";

/** Loading placeholder shaped like the report it is about to become. */
function ReportSkeleton() {
  return (
    <div className="container-page space-y-6 py-10" aria-busy="true">
      <span className="sr-only">Loading report…</span>
      <div className="animate-pulse rounded-xl border border-line bg-card p-6">
        <div className="flex flex-col gap-10 lg:flex-row lg:items-center">
          <div className="flex-1 space-y-5">
            <div className="h-8 w-2/3 rounded-md bg-raised" />
            <div className="h-4 w-1/2 rounded-md bg-raised" />
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
              {Array.from({ length: 6 }, (_, i) => (
                <div key={i} className="space-y-2">
                  <div className="h-2.5 w-16 rounded bg-raised" />
                  <div className="h-4 w-24 rounded bg-raised" />
                </div>
              ))}
            </div>
          </div>
          <div className="h-48 w-48 shrink-0 self-center rounded-full border-8 border-raised" />
        </div>
      </div>
      <div className="grid animate-pulse grid-cols-1 gap-6 lg:grid-cols-3">
        {Array.from({ length: 3 }, (_, i) => (
          <div key={i} className="h-56 rounded-xl border border-line bg-card" />
        ))}
      </div>
      <div className="h-72 animate-pulse rounded-xl border border-line bg-card" />
    </div>
  );
}

export function ReportClient({ id, demo }: { id?: string; demo?: boolean }) {
  const [report, setReport] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const promise = demo ? getDemo() : getReport(id as string);
    promise
      .then((r) => active && setReport(r))
      .catch(
        (e) =>
          active &&
          setError(
            e instanceof ApiError ? e.message : "Could not load this report.",
          ),
      );
    return () => {
      active = false;
    };
  }, [id, demo]);

  // While the dynamic sandbox job is still running, re-fetch the report until it settles.
  useEffect(() => {
    if (demo || !report) return;
    const status = report.sandbox?.status;
    if (status !== "PENDING" && status !== "RUNNING") return;
    const timer = setTimeout(() => {
      getReport(id as string)
        .then(setReport)
        .catch(() => {
          /* keep the last good report; a transient error shouldn't blank the page */
        });
    }, 2000);
    return () => clearTimeout(timer);
  }, [report, id, demo]);

  if (error) {
    return (
      <div className="container-page py-24">
        <div className="mx-auto max-w-md rounded-xl border border-danger/30 bg-danger/5 p-8 text-center">
          <span className="inline-flex text-danger">
            <AlertIcon className="h-10 w-10" />
          </span>
          <h1 className="mt-4 font-display text-lg font-semibold">
            Report unavailable
          </h1>
          <p className="mt-2 text-sm text-muted">{error}</p>
          <p className="mt-1.5 text-xs text-faint">
            Reports are kept in memory and expire when the analyzer restarts.
          </p>
          <Link
            href="/"
            className="mt-6 inline-flex rounded-lg bg-primary px-5 py-2.5 text-sm font-medium text-bg transition hover:brightness-110"
          >
            Scan a plugin
          </Link>
        </div>
      </div>
    );
  }

  if (!report) return <ReportSkeleton />;

  return <ReportView report={report} />;
}

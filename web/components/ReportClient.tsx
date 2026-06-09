"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import type { ScanResult } from "@/lib/types";
import { ApiError, getDemo, getReport } from "@/lib/api";
import { ReportView } from "./ReportView";
import { AlertIcon } from "./icons";

export function ReportClient({ id, demo }: { id?: string; demo?: boolean }) {
  const [report, setReport] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const promise = demo ? getDemo() : getReport(id as string);
    promise
      .then((r) => active && setReport(r))
      .catch((e) =>
        active &&
        setError(
          e instanceof ApiError ? e.message : "Could not load this report.",
        ),
      );
    return () => {
      active = false;
    };
  }, [id, demo]);

  if (error) {
    return (
      <div className="container-page py-20">
        <div className="mx-auto max-w-md rounded-2xl border border-danger/40 bg-danger/10 p-8 text-center">
          <span className="inline-flex text-danger">
            <AlertIcon className="h-10 w-10" />
          </span>
          <h1 className="mt-4 text-lg font-semibold">Report unavailable</h1>
          <p className="mt-2 text-sm text-muted">{error}</p>
          <p className="mt-1 text-xs text-muted">
            Reports are kept in memory and expire when the analyzer restarts.
          </p>
          <Link
            href="/"
            className="mt-5 inline-flex rounded-lg bg-primary px-4 py-2 text-sm font-medium text-bg hover:bg-primary/90 transition"
          >
            Scan a plugin
          </Link>
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="container-page py-32 flex flex-col items-center gap-4">
        <span className="h-10 w-10 rounded-full border-2 border-primary/30 border-t-primary animate-spin" />
        <p className="text-muted text-sm">Loading report…</p>
      </div>
    );
  }

  return <ReportView report={report} />;
}

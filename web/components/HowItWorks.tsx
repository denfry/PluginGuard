import { UploadIcon, CrosshairIcon, ShieldIcon } from "./icons";
import type { ReactNode } from "react";

interface Step {
  icon: ReactNode;
  title: string;
  body: string;
}

// A genuine sequence — drop, analyse, decide — so the numbering carries meaning.
const STEPS: Step[] = [
  {
    icon: <UploadIcon className="h-5 w-5" />,
    title: "Drop a file",
    body: "A plugin, mod, or resource / data pack — up to 50 MB. Nothing installs, and nothing runs on your server.",
  },
  {
    icon: <CrosshairIcon className="h-5 w-5" />,
    title: "Static + sandbox",
    body: "Every class is read for dangerous calls and indicators, then the artifact is run in a network-blocked container to catch what static analysis can't see.",
  },
  {
    icon: <ShieldIcon className="h-5 w-5" />,
    title: "A verdict you can act on",
    body: "Five scored axes, findings ranked by severity with exact locations, and one plain recommendation: install, install with care, or don't.",
  },
];

export function HowItWorks() {
  return (
    <ol className="relative grid gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-3">
      {STEPS.map((s, i) => (
        <li key={s.title} className="relative bg-bg p-6 lg:p-7">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-faint">
              step {String(i + 1).padStart(2, "0")}
            </span>
            <span className="text-primary">{s.icon}</span>
          </div>
          <h3 className="mt-5 font-display text-lg font-medium text-ink">
            {s.title}
          </h3>
          <p className="mt-2 text-sm leading-relaxed text-muted">{s.body}</p>
        </li>
      ))}
    </ol>
  );
}

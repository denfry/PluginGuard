import { CrosshairIcon, EyeIcon, AlertIcon } from "./icons";
import type { ReactNode } from "react";

interface Assurance {
  icon: ReactNode;
  title: string;
  body: string;
}

const ASSURANCES: Assurance[] = [
  {
    icon: <CrosshairIcon className="h-5 w-5" />,
    title: "Never runs on your server",
    body: "The artifact is only executed inside a sandboxed, network-blocked container in our pipeline — never on your machine, and never against live players.",
  },
  {
    icon: <EyeIcon className="h-5 w-5" />,
    title: "Nothing is kept",
    body: "Reports live in memory and expire when the analyzer restarts. Your upload isn't persisted to disk after it's scanned.",
  },
  {
    icon: <AlertIcon className="h-5 w-5" />,
    title: "Honest about limits",
    body: "A clean report isn't a guarantee of safety. Every report says plainly what static and dynamic analysis can and cannot prove.",
  },
];

export function TrustGrid() {
  return (
    <div className="grid gap-2.5 sm:grid-cols-3">
      {ASSURANCES.map((a) => (
        <div
          key={a.title}
          className="rounded-xl border border-line bg-card p-6 transition-colors duration-200 hover:border-line-strong"
        >
          <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-primary/30 bg-primary/10 text-primary">
            {a.icon}
          </span>
          <h3 className="mt-4 font-display text-base font-medium text-ink">
            {a.title}
          </h3>
          <p className="mt-2 text-sm leading-relaxed text-muted">{a.body}</p>
        </div>
      ))}
    </div>
  );
}

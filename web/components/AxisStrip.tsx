import { ShieldIcon, BoltIcon, BoxIcon, CodeIcon, FileIcon } from "./icons";
import type { ReactNode } from "react";

interface Axis {
  icon: ReactNode;
  name: string;
  body: string;
}

// Mirrors the five axes the engine scores (AXIS_LABEL) so the homepage and the
// report speak the same language.
const AXES: Axis[] = [
  {
    icon: <ShieldIcon className="h-4 w-4" />,
    name: "Security",
    body: "Malware signatures, exfiltration, dangerous calls.",
  },
  {
    icon: <BoltIcon className="h-4 w-4" />,
    name: "Performance",
    body: "Main-thread blocking, lag risk, heavy I/O.",
  },
  {
    icon: <BoxIcon className="h-4 w-4" />,
    name: "Compatibility",
    body: "Version-pinned internals and breakage risk.",
  },
  {
    icon: <CodeIcon className="h-4 w-4" />,
    name: "Code health",
    body: "Obfuscation and auditability of the build.",
  },
  {
    icon: <FileIcon className="h-4 w-4" />,
    name: "Legal / license",
    body: "Bundled-license conflicts and provenance.",
  },
];

export function AxisStrip() {
  return (
    <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-5">
      {AXES.map((a) => (
        <div
          key={a.name}
          className="hover-lift flex flex-col gap-2.5 rounded-lg border border-line bg-panel p-4"
        >
          <span className="flex h-8 w-8 items-center justify-center rounded-md border border-line text-primary">
            {a.icon}
          </span>
          <h3 className="font-display text-sm font-medium text-ink">{a.name}</h3>
          <p className="text-xs leading-snug text-muted">{a.body}</p>
        </div>
      ))}
    </div>
  );
}

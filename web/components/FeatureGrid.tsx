import {
  CodeIcon,
  NetworkIcon,
  BoxIcon,
  EyeIcon,
  FileIcon,
  FingerprintIcon,
} from "./icons";
import type { ReactNode } from "react";

interface Feature {
  icon: ReactNode;
  title: string;
  points: string[];
}

const FEATURES: Feature[] = [
  {
    icon: <CodeIcon className="h-5 w-5" />,
    title: "Bytecode",
    points: ["Runtime.exec", "Class loading", "Reflection"],
  },
  {
    icon: <NetworkIcon className="h-5 w-5" />,
    title: "Network",
    points: ["Webhooks", "IPs & URLs", "Sockets"],
  },
  {
    icon: <BoxIcon className="h-5 w-5" />,
    title: "Dependencies",
    points: ["Bundled libs", "SBOM", "Shaded jars"],
  },
  {
    icon: <EyeIcon className="h-5 w-5" />,
    title: "Obfuscation",
    points: ["Base64 blobs", "Class names", "Reflection density"],
  },
  {
    icon: <FileIcon className="h-5 w-5" />,
    title: "plugin.yml",
    points: ["Commands", "Permissions", "Main class"],
  },
  {
    icon: <FingerprintIcon className="h-5 w-5" />,
    title: "Provenance",
    points: ["SHA-256", "Source check", "Signatures"],
  },
];

export function FeatureGrid() {
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-line">
      <div className="grid grid-cols-1 gap-px sm:grid-cols-2 lg:grid-cols-3">
        {FEATURES.map((f, i) => (
          <div
            key={f.title}
            className="group bg-bg p-6 transition-colors duration-200 hover:bg-card"
          >
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs text-faint transition-colors duration-200 group-hover:text-primary">
                {String(i + 1).padStart(2, "0")}
              </span>
              <span className="text-faint transition-colors duration-200 group-hover:text-primary">
                {f.icon}
              </span>
            </div>
            <h3 className="mt-5 font-display text-lg font-medium text-ink">
              {f.title}
            </h3>
            <ul className="mt-2.5 space-y-1.5">
              {f.points.map((p) => (
                <li key={p} className="font-mono text-xs text-muted">
                  <span className="mr-2 text-primary/60">+</span>
                  {p}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

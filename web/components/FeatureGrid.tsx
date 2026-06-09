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
    icon: <CodeIcon className="h-6 w-6" />,
    title: "Bytecode",
    points: ["Runtime.exec", "Class loading", "Reflection"],
  },
  {
    icon: <NetworkIcon className="h-6 w-6" />,
    title: "Network",
    points: ["Webhooks", "IPs & URLs", "Sockets"],
  },
  {
    icon: <BoxIcon className="h-6 w-6" />,
    title: "Dependencies",
    points: ["Bundled libs", "SBOM", "Shaded jars"],
  },
  {
    icon: <EyeIcon className="h-6 w-6" />,
    title: "Obfuscation",
    points: ["Base64 blobs", "Class names", "Reflection density"],
  },
  {
    icon: <FileIcon className="h-6 w-6" />,
    title: "plugin.yml",
    points: ["Commands", "Permissions", "Main class"],
  },
  {
    icon: <FingerprintIcon className="h-6 w-6" />,
    title: "Provenance",
    points: ["SHA-256", "Source check", "Signatures"],
  },
];

export function FeatureGrid() {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
      {FEATURES.map((f) => (
        <div
          key={f.title}
          className="rounded-xl border border-line bg-card/50 p-5 hover:border-primary/40 transition"
        >
          <div className="flex items-center gap-3">
            <span className="text-primary">{f.icon}</span>
            <h3 className="font-semibold text-ink">{f.title}</h3>
          </div>
          <ul className="mt-3 space-y-1 text-sm text-muted">
            {f.points.map((p) => (
              <li key={p} className="flex items-center gap-2">
                <span className="h-1 w-1 rounded-full bg-primary/60" />
                {p}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

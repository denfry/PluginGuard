"use client";

import {
  CodeIcon,
  NetworkIcon,
  BoxIcon,
  EyeIcon,
  FileIcon,
  FingerprintIcon,
} from "./icons";
import { useI18n } from "@/lib/i18n";
import type { ReactNode } from "react";

interface Feature {
  icon: ReactNode;
  titleKey: string;
  pointKeys: string[];
}

const FEATURES: Feature[] = [
  {
    icon: <CodeIcon className="h-5 w-5" />,
    titleKey: "feature.bytecode",
    pointKeys: ["feature.bytecode.p1", "feature.bytecode.p2", "feature.bytecode.p3"],
  },
  {
    icon: <NetworkIcon className="h-5 w-5" />,
    titleKey: "feature.network",
    pointKeys: ["feature.network.p1", "feature.network.p2", "feature.network.p3"],
  },
  {
    icon: <BoxIcon className="h-5 w-5" />,
    titleKey: "feature.deps",
    pointKeys: ["feature.deps.p1", "feature.deps.p2", "feature.deps.p3"],
  },
  {
    icon: <EyeIcon className="h-5 w-5" />,
    titleKey: "feature.obf",
    pointKeys: ["feature.obf.p1", "feature.obf.p2", "feature.obf.p3"],
  },
  {
    icon: <FileIcon className="h-5 w-5" />,
    titleKey: "feature.yml",
    pointKeys: ["feature.yml.p1", "feature.yml.p2", "feature.yml.p3"],
  },
  {
    icon: <FingerprintIcon className="h-5 w-5" />,
    titleKey: "feature.prov",
    pointKeys: ["feature.prov.p1", "feature.prov.p2", "feature.prov.p3"],
  },
];

export function FeatureGrid() {
  const { t } = useI18n();
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-line">
      <div className="grid grid-cols-1 gap-px sm:grid-cols-2 lg:grid-cols-3">
        {FEATURES.map((f, i) => (
          <div
            key={f.titleKey}
            className="group bg-bg p-6 transition-colors duration-200 hover:bg-card"
          >
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs text-faint transition-colors duration-200 group-hover:text-primary">
                {String(i + 1).padStart(2, "0")}
              </span>
              <span className="text-faint transition-all duration-200 group-hover:text-primary group-hover:scale-110">
                {f.icon}
              </span>
            </div>
            <h3 className="mt-5 font-display text-lg font-medium text-ink">
              {t(f.titleKey)}
            </h3>
            <ul className="mt-2.5 space-y-1.5">
              {f.pointKeys.map((p) => (
                <li key={p} className="font-mono text-xs text-muted">
                  <span className="mr-2 text-primary/60">+</span>
                  {t(p)}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

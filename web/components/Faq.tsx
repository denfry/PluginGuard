import { ChevronIcon } from "./icons";

const FAQS: { q: string; a: string }[] = [
  {
    q: "Does PluginGuard run the plugin on my server?",
    a: "No. Static analysis never executes code. The optional sandbox runs the artifact in an isolated, network-blocked container inside our pipeline — never on your server, and never against live players.",
  },
  {
    q: "Is my file stored anywhere?",
    a: "Reports are held in memory and expire when the analyzer restarts. Your upload isn't written to disk after the scan completes.",
  },
  {
    q: "What does the score mean?",
    a: "A 0–100 safety score where higher is safer, plus a breakdown across five axes. Findings are weighted by severity, and the recommendation turns the numbers into one clear action.",
  },
  {
    q: "Can it miss something?",
    a: "Yes. Obfuscation and reflection can hide behavior, and a sandbox only observes the code paths it triggers. Treat a report as strong evidence, not a warranty — that caveat ships with every result.",
  },
  {
    q: "What can I scan?",
    a: "Bukkit, Spigot and Paper plugins; BungeeCord and Velocity proxies; Forge, NeoForge, Fabric and Quilt mods; and resource / data packs.",
  },
];

export function Faq() {
  return (
    <div className="divide-y divide-line overflow-hidden rounded-xl border border-line bg-card">
      {FAQS.map((f) => (
        <details key={f.q} className="group">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-4 px-5 py-4 transition-colors hover:bg-raised/40">
            <span className="font-display text-base font-medium text-ink">
              {f.q}
            </span>
            <ChevronIcon className="h-4 w-4 shrink-0 text-faint transition-transform duration-200 group-open:rotate-180" />
          </summary>
          <p className="px-5 pb-5 text-sm leading-relaxed text-muted">{f.a}</p>
        </details>
      ))}
    </div>
  );
}

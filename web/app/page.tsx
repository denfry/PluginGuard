import Link from "next/link";
import { Dropzone } from "@/components/Dropzone";
import { FeatureGrid } from "@/components/FeatureGrid";
import { ScoreGauge } from "@/components/ScoreGauge";
import { VerdictBadge, SeverityPill } from "@/components/Badges";
import { ArrowRightIcon } from "@/components/icons";
import type { Severity } from "@/lib/types";

// Mirrors the findings served by GET /api/demo so the teaser matches the real demo report.
const SAMPLE_FINDINGS: { sev: Severity; title: string; loc: string }[] = [
  {
    sev: "HIGH",
    title: "External Discord webhook",
    loc: "WebhookClient#sendModerationLog",
  },
  {
    sev: "MEDIUM",
    title: "Reflection used to access server internals",
    loc: "NMSResolver#resolve",
  },
  {
    sev: "LOW",
    title: "Makes HTTP requests",
    loc: "UpdateChecker#check",
  },
];

export default function Home() {
  return (
    <div className="container-page">
      {/* Hero + uploader */}
      <section className="grid items-center gap-12 py-16 lg:grid-cols-[1.05fr_1fr] lg:gap-16 lg:py-24">
        <div className="space-y-7">
          <p className="micro-label text-primary">
            {"//"} minecraft plugin security
          </p>
          <h1 className="font-display text-4xl font-semibold leading-[1.08] tracking-tight text-ink lg:text-[3.4rem]">
            Know what a plugin <span className="text-primary">really does</span>{" "}
            before you run it.
          </h1>
          <p className="max-w-xl text-lg leading-relaxed text-muted">
            Upload a <span className="font-mono text-sm text-ink">.jar</span>{" "}
            and get a forensic report — dangerous calls, network indicators,
            obfuscation scoring and{" "}
            <span className="font-mono text-sm text-ink">plugin.yml</span>{" "}
            validation. Static analysis plus an isolated sandbox run.
          </p>
          <p className="micro-label leading-6 text-faint">
            runtime.exec · webhooks · classloading · obfuscation · plugin.yml
          </p>
        </div>

        <Dropzone />
      </section>

      {/* Analysis pipeline */}
      <section id="what-we-scan" className="scroll-mt-20 py-12">
        <div className="mb-8 flex items-end justify-between gap-6">
          <div>
            <p className="micro-label text-primary">{"//"} analysis pipeline</p>
            <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight">
              Six passes over every JAR
            </h2>
          </div>
          <p className="hidden max-w-xs text-right text-sm text-muted sm:block">
            Each upload runs the full pipeline — no pass is skipped, no result
            is cached from another file.
          </p>
        </div>
        <FeatureGrid />
      </section>

      {/* Example report teaser */}
      <section className="py-12">
        <div className="rounded-xl border border-line bg-card p-6 lg:p-10">
          <div className="flex flex-col items-center gap-10 lg:flex-row lg:gap-14">
            <div className="flex shrink-0 flex-col items-center gap-3">
              <ScoreGauge score={78} />
              <VerdictBadge verdict="MEDIUM_RISK" />
            </div>

            <div className="min-w-0 flex-1 space-y-5 text-center lg:text-left">
              <div>
                <p className="micro-label text-primary">
                  {"//"} sample verdict
                </p>
                <h2 className="mt-2 font-display text-2xl font-semibold tracking-tight">
                  Reports you can act on
                </h2>
              </div>
              <p className="mx-auto max-w-lg text-muted lg:mx-0">
                Every finding names the exact class and method behind it, what
                the risk is, and what to check — backed by network, filesystem
                and dependency summaries.
              </p>

              <div className="divide-y divide-line overflow-hidden rounded-lg border border-line bg-bg text-left">
                {SAMPLE_FINDINGS.map((f) => (
                  <div
                    key={f.title}
                    className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5"
                  >
                    <SeverityPill severity={f.sev} />
                    <span className="text-sm font-medium text-ink">
                      {f.title}
                    </span>
                    <code className="ml-auto hidden font-mono text-[11px] text-faint sm:block">
                      {f.loc}
                    </code>
                  </div>
                ))}
              </div>

              <Link
                href="/demo"
                className="inline-flex items-center gap-2 rounded-lg bg-primary px-5 py-2.5 text-sm font-medium text-bg transition hover:brightness-110"
              >
                Open the demo report
                <ArrowRightIcon className="h-4 w-4" />
              </Link>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

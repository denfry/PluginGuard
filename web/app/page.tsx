import Link from "next/link";
import { Dropzone } from "@/components/Dropzone";
import { FeatureGrid } from "@/components/FeatureGrid";
import { HowItWorks } from "@/components/HowItWorks";
import { AxisStrip } from "@/components/AxisStrip";
import { TrustGrid } from "@/components/TrustGrid";
import { Faq } from "@/components/Faq";
import { CallToAction } from "@/components/CallToAction";
import { SectionHeading } from "@/components/SectionHeading";
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
      <section
        id="top"
        className="grid items-center gap-12 py-16 lg:grid-cols-[1.05fr_1fr] lg:gap-16 lg:py-24"
      >
        <div className="space-y-7">
          <p className="reveal micro-label flex items-center gap-2 text-primary">
            <span
              className="pulse-dot inline-block h-1.5 w-1.5 rounded-full bg-primary"
              aria-hidden
            />
            {"//"} minecraft plugin &amp; mod security
          </p>
          <h1
            className="reveal font-display text-4xl font-semibold leading-[1.08] tracking-tight text-ink lg:text-[3.4rem]"
            style={{ animationDelay: "0.08s" }}
          >
            Know what a plugin{" "}
            <span className="text-primary text-glow">really does</span> before
            you run it.
          </h1>
          <p
            className="reveal max-w-xl text-lg leading-relaxed text-muted"
            style={{ animationDelay: "0.16s" }}
          >
            Upload a plugin, mod, or resource pack and get a forensic report —
            dangerous calls, network indicators, obfuscation scoring,
            performance traps and{" "}
            <span className="font-mono text-sm text-ink">plugin.yml</span>{" "}
            validation. Static bytecode analysis plus an isolated sandbox run.
          </p>
          <p
            className="reveal micro-label leading-6 text-faint"
            style={{ animationDelay: "0.24s" }}
          >
            runtime.exec · webhooks · classloading · obfuscation · main-thread
            lag · plugin.yml
          </p>
        </div>

        <div className="reveal" style={{ animationDelay: "0.12s" }}>
          <Dropzone />
        </div>
      </section>

      {/* How it works — the static + sandbox method */}
      <section className="reveal-on-scroll py-12">
        <SectionHeading
          eyebrow="how it works"
          title="From upload to verdict"
          aside="Static analysis reads the code; the sandbox watches it run. You get both."
        />
        <HowItWorks />
      </section>

      {/* What static analysis inspects */}
      <section id="what-we-scan" className="scroll-mt-20 py-12">
        <SectionHeading
          eyebrow="static analysis"
          title="Six passes over every build"
          aside="Each upload runs the full pipeline — no pass is skipped, no result is cached from another file."
        />
        <FeatureGrid />
      </section>

      {/* The five scoring axes */}
      <section className="reveal-on-scroll py-12">
        <SectionHeading
          eyebrow="scoring model"
          title="Graded on five axes"
          aside="One number hides trade-offs. PluginGuard scores each concern on its own."
        />
        <AxisStrip />
      </section>

      {/* Example report teaser */}
      <section className="reveal-on-scroll py-12">
        <div className="hover-lift rounded-xl border border-line bg-card p-6 lg:p-10">
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
                className="btn-primary group inline-flex items-center gap-2 rounded-lg px-5 py-2.5 text-sm"
              >
                Open the demo report
                <ArrowRightIcon className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-0.5" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Trust & privacy */}
      <section className="reveal-on-scroll py-12">
        <SectionHeading
          eyebrow="trust"
          title="Built to be doubted"
          aside="A security tool only earns trust by being clear about what it does with your file."
        />
        <TrustGrid />
      </section>

      {/* FAQ */}
      <section className="reveal-on-scroll py-12">
        <SectionHeading eyebrow="questions" title="The short answers" />
        <Faq />
      </section>

      {/* Closing CTA */}
      <section className="reveal-on-scroll pb-4 pt-8">
        <CallToAction />
      </section>
    </div>
  );
}

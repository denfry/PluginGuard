"use client";

import Link from "next/link";
import { Dropzone } from "@/components/Dropzone";
import { FeatureGrid } from "@/components/FeatureGrid";
import { ScoreGauge } from "@/components/ScoreGauge";
import { VerdictBadge, SeverityPill } from "@/components/Badges";
import { Reveal } from "@/components/Reveal";
import { ArrowRightIcon } from "@/components/icons";
import { useI18n } from "@/lib/i18n";
import type { Severity } from "@/lib/types";

export default function Home() {
  const { t } = useI18n();

  // Mirrors the findings served by GET /api/demo so the teaser matches the real demo report.
  const SAMPLE_FINDINGS: { sev: Severity; title: string; loc: string }[] = [
    { sev: "HIGH", title: t("home.sample.f1"), loc: t("home.sample.f1.loc") },
    { sev: "MEDIUM", title: t("home.sample.f2"), loc: t("home.sample.f2.loc") },
    { sev: "LOW", title: t("home.sample.f3"), loc: t("home.sample.f3.loc") },
  ];

  return (
    <div className="container-page">
      {/* Hero + uploader */}
      <section className="grid items-center gap-12 py-16 lg:grid-cols-[1.05fr_1fr] lg:gap-16 lg:py-24">
        <div className="space-y-7">
          <p className="micro-label anim-fade-up text-primary" style={{ animationDelay: "0ms" }}>
            {"//"} {t("home.kicker")}
          </p>
          <h1
            className="anim-fade-up font-display text-4xl font-semibold leading-[1.08] tracking-tight text-ink lg:text-[3.4rem]"
            style={{ animationDelay: "80ms" }}
          >
            {t("home.title.a")} <span className="text-primary">{t("home.title.b")}</span>{" "}
            {t("home.title.c")}
          </h1>
          <p
            className="anim-fade-up max-w-xl text-lg leading-relaxed text-muted"
            style={{ animationDelay: "160ms" }}
          >
            {t("home.lead.a")}{" "}
            <span className="font-mono text-sm text-ink">.jar</span>{" "}
            {t("home.lead.b")}{" "}
            <span className="font-mono text-sm text-ink">plugin.yml</span>
            {t("home.lead.c")}
          </p>
          <p
            className="micro-label anim-fade-up leading-6 text-faint"
            style={{ animationDelay: "240ms" }}
          >
            {t("home.lead.tags")}
          </p>
        </div>

        <div className="anim-fade-up" style={{ animationDelay: "200ms" }}>
          <Dropzone />
        </div>
      </section>

      {/* Analysis pipeline */}
      <section id="what-we-scan" className="scroll-mt-20 py-12">
        <Reveal className="mb-8 flex items-end justify-between gap-6">
          <div>
            <p className="micro-label text-primary">
              {"//"} {t("home.pipeline.kicker")}
            </p>
            <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight">
              {t("home.pipeline.title")}
            </h2>
          </div>
          <p className="hidden max-w-xs text-right text-sm text-muted sm:block">
            {t("home.pipeline.note")}
          </p>
        </Reveal>
        <Reveal delay={80}>
          <FeatureGrid />
        </Reveal>
      </section>

      {/* Example report teaser */}
      <section className="py-12">
        <Reveal className="anim-glow rounded-xl border border-line bg-card p-6 lg:p-10">
          <div className="flex flex-col items-center gap-10 lg:flex-row lg:gap-14">
            <div className="flex shrink-0 flex-col items-center gap-3 anim-float">
              <ScoreGauge score={78} />
              <VerdictBadge verdict="MEDIUM_RISK" />
            </div>

            <div className="min-w-0 flex-1 space-y-5 text-center lg:text-left">
              <div>
                <p className="micro-label text-primary">
                  {"//"} {t("home.sample.kicker")}
                </p>
                <h2 className="mt-2 font-display text-2xl font-semibold tracking-tight">
                  {t("home.sample.title")}
                </h2>
              </div>
              <p className="mx-auto max-w-lg text-muted lg:mx-0">
                {t("home.sample.body")}
              </p>

              <div className="divide-y divide-line overflow-hidden rounded-lg border border-line bg-bg text-left">
                {SAMPLE_FINDINGS.map((f) => (
                  <div
                    key={f.title}
                    className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 transition-colors hover:bg-card"
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
                className="btn-sheen inline-flex items-center gap-2 rounded-lg bg-primary px-5 py-2.5 text-sm font-medium text-bg transition hover:brightness-110"
              >
                {t("home.sample.cta")}
                <ArrowRightIcon className="h-4 w-4" />
              </Link>
            </div>
          </div>
        </Reveal>
      </section>
    </div>
  );
}

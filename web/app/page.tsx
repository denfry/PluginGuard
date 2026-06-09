import Link from "next/link";
import { Dropzone } from "@/components/Dropzone";
import { FeatureGrid } from "@/components/FeatureGrid";
import { ScoreGauge } from "@/components/ScoreGauge";
import { VerdictBadge, CountChip } from "@/components/Badges";

export default function Home() {
  return (
    <div className="container-page">
      {/* Hero + uploader */}
      <section className="py-14 lg:py-20 grid lg:grid-cols-2 gap-10 lg:gap-14 items-center">
        <div className="space-y-6">
          <span className="inline-flex items-center gap-2 rounded-full border border-line bg-card/60 px-3 py-1 text-xs text-muted">
            <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
            Static analysis · bytecode · no sandbox
          </span>
          <h1 className="text-4xl lg:text-5xl font-semibold tracking-tight leading-[1.1]">
            Deep security analysis for{" "}
            <span className="text-primary">Minecraft plugins</span>
          </h1>
          <p className="text-lg text-muted max-w-xl">
            Upload a <span className="font-mono text-ink">.jar</span> and see
            what it really does before you install it on your server — dangerous
            calls, network indicators, obfuscation and{" "}
            <span className="font-mono text-ink">plugin.yml</span> validation.
          </p>
          <div className="flex flex-wrap gap-3 text-xs text-muted">
            {["Bytecode", "Dependencies", "URLs", "Obfuscation", "YAML"].map(
              (t) => (
                <span
                  key={t}
                  className="rounded-md border border-line bg-card/40 px-2.5 py-1"
                >
                  {t}
                </span>
              ),
            )}
          </div>
        </div>

        <div>
          <Dropzone />
        </div>
      </section>

      {/* What we scan */}
      <section id="what-we-scan" className="py-10 scroll-mt-20">
        <div className="flex items-end justify-between mb-6">
          <h2 className="text-2xl font-semibold">What we scan</h2>
          <p className="text-sm text-muted hidden sm:block">
            Six analysis passes over every uploaded JAR
          </p>
        </div>
        <FeatureGrid />
      </section>

      {/* Example result */}
      <section className="py-10">
        <div className="rounded-2xl border border-line bg-card/50 p-6 lg:p-8">
          <div className="flex flex-col lg:flex-row gap-8 items-center">
            <ScoreGauge score={78} />
            <div className="flex-1 space-y-4 text-center lg:text-left">
              <h2 className="text-xl font-semibold">Example result</h2>
              <div className="flex justify-center lg:justify-start">
                <VerdictBadge verdict="MEDIUM_RISK" />
              </div>
              <p className="text-muted max-w-lg">
                A real report breaks the score down into findings grouped by
                severity, with the exact class and method behind each one, plus
                network, filesystem and dependency summaries.
              </p>
              <div className="grid grid-cols-4 gap-2 max-w-sm mx-auto lg:mx-0">
                <CountChip label="Crit" value={0} />
                <CountChip label="High" value={1} />
                <CountChip label="Med" value={1} />
                <CountChip label="Low" value={3} />
              </div>
              <Link
                href="/demo"
                className="inline-flex rounded-lg border border-primary/40 bg-primary/10 px-4 py-2 text-sm font-medium text-primary hover:bg-primary/20 transition"
              >
                Open demo report →
              </Link>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
